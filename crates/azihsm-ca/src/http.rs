//! Bounded Actix Web HTTP service and dedicated readiness watcher.

use crate::authority::{LoadedAuthority, certificate_bytes, certificate_status, issue};
use crate::cli::ServeArgs;
use crate::csr::parse_and_authorize;
use crate::encoding::is_lower_hex_32;
use crate::error::{Error, ErrorClass, Result};
use crate::policy::warning_text;
use crate::state::{DirectoryWatcher, WatchResult};
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::{KeepAlive, StatusCode, header};
use actix_web::middleware::Next;
use actix_web::{App, FromRequest, HttpMessage, HttpRequest, HttpResponse, HttpServer, web};
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::mem::ManuallyDrop;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};

const REQUEST_LIMIT: usize = 16_384;
const REQUEST_LIFETIME: Duration = Duration::from_secs(10);

struct AcceptedConnection {
    accepted: Instant,
    _abort: Arc<ConnectionAbort>,
}

struct ConnectionAbort {
    socket: TcpStream,
}

#[derive(Clone, Copy)]
struct RequestDeadline {
    processing: Instant,
}

#[derive(Clone, Copy)]
struct DeadlineConfig(Duration);

struct Pkcs10Request(web::Bytes);

impl FromRequest for Pkcs10Request {
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<Self, Self::Error>>>>;

    fn from_request(request: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        let payload = web::Payload::from_request(request, payload);
        let deadline = request
            .extensions()
            .get::<RequestDeadline>()
            .copied()
            .map_or_else(
                || tokio::time::Instant::now() + REQUEST_LIFETIME,
                |value| tokio::time::Instant::from_std(value.processing),
            );
        Box::pin(async move {
            let payload = payload.await?;
            match tokio::time::timeout_at(deadline, payload.to_bytes_limited(REQUEST_LIMIT)).await {
                Err(_) => Err(actix_web::error::InternalError::from_response(
                    "busy",
                    request_error(StatusCode::SERVICE_UNAVAILABLE, "busy", "deadline"),
                )
                .into()),
                Ok(Ok(Ok(bytes))) => Ok(Self(bytes)),
                Ok(Err(_)) => Err(actix_web::error::InternalError::from_response(
                    "request_too_large",
                    request_error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request_too_large",
                        "malformed",
                    ),
                )
                .into()),
                Ok(Ok(Err(_))) => Err(actix_web::error::InternalError::from_response(
                    "malformed_request",
                    request_error(StatusCode::BAD_REQUEST, "malformed_request", "malformed"),
                )
                .into()),
            }
        })
    }
}

struct AppState {
    authority: Arc<LoadedAuthority>,
    policy: ServeArgs,
    issuance: Arc<Mutex<()>>,
    ready: Arc<AtomicBool>,
    readiness_pending: Arc<AtomicBool>,
    admission: Arc<Semaphore>,
    blocking: Arc<Semaphore>,
    in_flight: Arc<AtomicUsize>,
    limiter: Mutex<RateLimiter>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    schema_version: u32,
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

pub fn serve(args: ServeArgs, loaded: LoadedAuthority) -> Result<()> {
    eprint!("{}", warning_text());
    let authority = Arc::new(loaded);
    let issuance = Arc::new(Mutex::new(()));
    let ready = Arc::new(AtomicBool::new(false));
    let pending = Arc::new(AtomicBool::new(true));
    let watcher = ReadinessWatcher::start(
        Arc::clone(&authority),
        Arc::clone(&issuance),
        Arc::clone(&ready),
        Arc::clone(&pending),
    )?;
    let state = web::Data::new(AppState {
        authority,
        policy: args.clone(),
        issuance,
        ready,
        readiness_pending: pending,
        admission: Arc::new(Semaphore::new(32)),
        blocking: Arc::new(Semaphore::new(4)),
        in_flight: Arc::new(AtomicUsize::new(0)),
        limiter: Mutex::new(RateLimiter::new()),
    });
    let listen = args.listen;
    let max_connections = usize::from(args.max_connections.min(64));
    let result = actix_web::rt::System::new().block_on(async move {
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .app_data(web::PayloadConfig::new(REQUEST_LIMIT))
                .app_data(web::Data::new(DeadlineConfig(REQUEST_LIFETIME)))
                .wrap(actix_web::middleware::from_fn(protocol_middleware))
                .service(api_scope())
        })
        .workers(1)
        .worker_max_blocking_threads(4)
        .max_connections(max_connections)
        .backlog(64)
        .client_request_timeout(REQUEST_LIFETIME)
        .client_disconnect_timeout(Duration::from_secs(2))
        .keep_alive(KeepAlive::Disabled)
        .shutdown_timeout(10)
        .shutdown_signal(async {
            let _ = actix_web::rt::signal::ctrl_c().await;
            tracing::info!(event = "server_shutdown_started");
        })
        .on_connect(|io, extensions| {
            register_connection_deadline(io, extensions, REQUEST_LIFETIME);
        })
        .bind(listen)
        .map_err(|error| Error::new(ErrorClass::Http, format!("HTTP bind failed: {error}")))?
        .run()
        .await
        .map_err(|error| Error::new(ErrorClass::Http, format!("HTTP server failed: {error}")))
    });
    finish_server_lifecycle(result, || watcher.stop_and_join())
}

fn finish_server_lifecycle<F>(server_result: Result<()>, stop_watcher: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    if let Err(error) = server_result {
        let _ = stop_watcher();
        return Err(error);
    }
    stop_watcher()?;
    tracing::info!(event = "server_shutdown_completed");
    Ok(())
}

fn api_scope() -> actix_web::Scope {
    web::scope("")
        .service(
            web::resource("/livez")
                .route(web::get().to(livez))
                .default_service(web::to(method_not_allowed)),
        )
        .service(
            web::resource("/readyz")
                .route(web::get().to(readyz))
                .default_service(web::to(method_not_allowed)),
        )
        .service(
            web::resource("/v1/ca")
                .route(web::get().to(metadata))
                .default_service(web::to(method_not_allowed)),
        )
        .service(
            web::resource("/v1/ca/root")
                .route(web::get().to(root))
                .default_service(web::to(method_not_allowed)),
        )
        .service(
            web::resource("/v1/certificates")
                .route(web::post().to(enroll))
                .default_service(web::to(method_not_allowed)),
        )
        .service(
            web::resource("/v1/certificates/{id}")
                .route(web::get().to(certificate))
                .default_service(web::to(method_not_allowed)),
        )
        .service(
            web::resource("/v1/certificates/{id}/status")
                .route(web::get().to(status))
                .default_service(web::to(method_not_allowed)),
        )
        .default_service(web::to(fallback))
}

fn register_connection_deadline(
    io: &dyn std::any::Any,
    extensions: &mut actix_web::dev::Extensions,
    lifetime: Duration,
) {
    let Some(stream) = io.downcast_ref::<actix_web::rt::net::TcpStream>() else {
        return;
    };
    let raw = stream.as_raw_socket();
    // SAFETY: `borrowed` is never dropped; `try_clone` creates the independently owned socket.
    let borrowed = ManuallyDrop::new(unsafe { TcpStream::from_raw_socket(raw) });
    let Ok(socket) = borrowed.try_clone() else {
        return;
    };
    let abort = Arc::new(ConnectionAbort { socket });
    let deadline_abort = Arc::clone(&abort);
    actix_web::rt::spawn(async move {
        tokio::time::sleep(lifetime).await;
        // SAFETY: the duplicated socket remains owned by `deadline_abort` for this call.
        unsafe {
            CancelIoEx(
                deadline_abort.socket.as_raw_socket() as HANDLE,
                std::ptr::null(),
            );
        }
        let _ = deadline_abort.socket.shutdown(Shutdown::Both);
    });
    extensions.insert(AcceptedConnection {
        accepted: Instant::now(),
        _abort: abort,
    });
}

async fn livez() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"schema_version":1,"live":true}))
}

async fn protocol_middleware(
    request: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> std::result::Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let accepted = request
        .request()
        .conn_data::<AcceptedConnection>()
        .map_or_else(Instant::now, |value| value.accepted);
    let lifetime = request
        .app_data::<web::Data<DeadlineConfig>>()
        .map_or(REQUEST_LIFETIME, |config| config.0);
    let deadline = accepted + lifetime;
    let response_reserve = Duration::from_millis(250).min(lifetime / 4);
    let processing_deadline = deadline.checked_sub(response_reserve).unwrap_or(deadline);
    request.extensions_mut().insert(RequestDeadline {
        processing: processing_deadline,
    });
    let malformed = request.version() != actix_web::http::Version::HTTP_11
        || request.headers().get_all(header::HOST).count() != 1
        || request.headers().contains_key(header::TRANSFER_ENCODING)
        || request.headers().contains_key(header::EXPECT)
        || request.headers().contains_key(header::UPGRADE)
        || request.headers().contains_key(header::TRAILER);
    let response = if Instant::now() >= deadline {
        request
            .into_response(request_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "deadline",
            ))
            .map_into_boxed_body()
    } else if malformed {
        request
            .into_response(request_error(
                StatusCode::BAD_REQUEST,
                "malformed_request",
                "malformed",
            ))
            .map_into_boxed_body()
    } else {
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(processing_deadline),
            next.call(request),
        )
        .await
        {
            Ok(response) => response?.map_into_boxed_body(),
            Err(_) => {
                return Err(actix_web::error::InternalError::from_response(
                    "busy",
                    request_error(StatusCode::SERVICE_UNAVAILABLE, "busy", "deadline"),
                )
                .into());
            }
        }
    };
    let mut response = response
        .map_body(|_, body| DeadlineBody {
            body: Box::pin(body),
            deadline,
        })
        .map_into_boxed_body();
    response.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    Ok(response)
}

async fn readyz(state: web::Data<AppState>) -> HttpResponse {
    readiness_response(is_ready(&state))
}

fn readiness_response(ready: bool) -> HttpResponse {
    if ready {
        HttpResponse::Ok().json(serde_json::json!({"schema_version":1,"ready":true}))
    } else {
        request_error(StatusCode::SERVICE_UNAVAILABLE, "ca_not_ready", "unready")
    }
}

async fn metadata(state: web::Data<AppState>) -> HttpResponse {
    if !is_ready(&state) {
        return request_error(StatusCode::SERVICE_UNAVAILABLE, "ca_not_ready", "unready");
    }
    metadata_response(&state.authority.authority.authority_id)
}

fn metadata_response(authority_id: &str) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "schema_version": 1,
        "authority_id": authority_id,
        "root": "/v1/ca/root",
        "certificates": "/v1/certificates"
    }))
}

async fn root(state: web::Data<AppState>) -> HttpResponse {
    if !is_ready(&state) {
        return request_error(StatusCode::SERVICE_UNAVAILABLE, "ca_not_ready", "unready");
    }
    HttpResponse::Ok()
        .content_type("application/pkix-cert")
        .body(state.authority.root_der.clone())
}

async fn enroll(
    request: HttpRequest,
    body: Pkcs10Request,
    state: web::Data<AppState>,
) -> HttpResponse {
    let deadline = request.extensions().get::<RequestDeadline>().map_or_else(
        || Instant::now() + REQUEST_LIFETIME,
        |value| value.processing,
    );
    if Instant::now() >= deadline {
        return request_error(StatusCode::SERVICE_UNAVAILABLE, "busy", "deadline");
    }
    if !is_ready(&state) {
        return request_error(StatusCode::SERVICE_UNAVAILABLE, "ca_not_ready", "unready");
    }
    if request.version() != actix_web::http::Version::HTTP_11
        || request.headers().contains_key(header::TRANSFER_ENCODING)
        || request.headers().contains_key(header::EXPECT)
    {
        return request_error(StatusCode::BAD_REQUEST, "malformed_request", "malformed");
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/pkcs10")
    {
        return request_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "malformed",
        );
    }
    let idempotency = match request
        .headers()
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
    {
        Some(value) if is_lower_hex_32(value) => value.to_owned(),
        _ => {
            return request_error(
                StatusCode::BAD_REQUEST,
                "invalid_idempotency_key",
                "malformed",
            );
        }
    };
    let body = body.0;
    let source = match request.peer_addr().map(|address| address.ip()) {
        Some(source) => source,
        None => return request_error(StatusCode::BAD_REQUEST, "malformed_request", "malformed"),
    };
    if !state
        .limiter
        .lock()
        .ok()
        .is_some_and(|mut limiter| limiter.allow(source))
    {
        return request_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "rate");
    }
    let admission = match Arc::clone(&state.admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return request_error(StatusCode::SERVICE_UNAVAILABLE, "busy", "admission");
        }
    };
    let blocking = match Arc::clone(&state.blocking).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return request_error(StatusCode::SERVICE_UNAVAILABLE, "busy", "admission");
        }
    };
    let parsed = match parse_and_authorize(&body, &state.policy) {
        Ok(parsed) => parsed,
        Err(error) => return mapped_error(&error),
    };
    if Instant::now() >= deadline {
        return request_error(StatusCode::SERVICE_UNAVAILABLE, "busy", "deadline");
    }
    let authority = Arc::clone(&state.authority);
    let policy = state.policy.clone();
    let issuance = Arc::clone(&state.issuance);
    let in_flight = Arc::clone(&state.in_flight);
    let source = source.to_string();
    let body = body.to_vec();
    let job = actix_web::rt::task::spawn_blocking(move || {
        let _guard = InFlightGuard::new(in_flight);
        let _permits: (OwnedSemaphorePermit, OwnedSemaphorePermit) = (admission, blocking);
        let _lock = issuance
            .lock()
            .map_err(|_| Error::new(ErrorClass::State, "issuance mutex poisoned"))?;
        issue(&authority, &policy, &parsed, &body, &idempotency, &source)
    });
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), job).await {
        Ok(Ok(Ok(issued))) => {
            let event = if issued.status == 200 {
                "enrollment_replayed"
            } else {
                "enrollment_accepted"
            };
            tracing::info!(event, issuance_id = issued.issuance_id);
            HttpResponse::build(
                StatusCode::from_u16(issued.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            )
            .insert_header(("X-AziHSM-Issuance-Id", issued.issuance_id))
            .content_type("application/pkix-cert")
            .body(issued.certificate)
        }
        Ok(Ok(Err(error))) => mapped_error(&error),
        _ => request_error(StatusCode::SERVICE_UNAVAILABLE, "busy", "deadline"),
    }
}

async fn certificate(path: web::Path<String>, state: web::Data<AppState>) -> HttpResponse {
    if !is_ready(&state) {
        return request_error(StatusCode::SERVICE_UNAVAILABLE, "ca_not_ready", "unready");
    }
    match certificate_bytes(&state.authority.state_dir, &path) {
        Ok(Some(bytes)) => HttpResponse::Ok()
            .content_type("application/pkix-cert")
            .body(bytes),
        _ => not_found(),
    }
}

async fn status(path: web::Path<String>, state: web::Data<AppState>) -> HttpResponse {
    if !is_ready(&state) {
        return request_error(StatusCode::SERVICE_UNAVAILABLE, "ca_not_ready", "unready");
    }
    match certificate_status(&state.authority.state_dir, &path) {
        Ok(Some(status)) => status_response(status),
        _ => not_found(),
    }
}

fn status_response(status: String) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(status)
}

async fn fallback(request: HttpRequest) -> HttpResponse {
    if matches!(
        *request.method(),
        actix_web::http::Method::GET | actix_web::http::Method::POST
    ) {
        not_found()
    } else {
        method_not_allowed().await
    }
}

async fn method_not_allowed() -> HttpResponse {
    json_error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
}

fn not_found() -> HttpResponse {
    json_error_with_message(
        StatusCode::NOT_FOUND,
        "certificate_not_found",
        "certificate not found",
    )
}

fn is_ready(state: &AppState) -> bool {
    state.ready.load(Ordering::Acquire) && !state.readiness_pending.load(Ordering::Acquire)
}

fn json_error(status: StatusCode, code: &'static str) -> HttpResponse {
    json_error_with_message(status, code, "request rejected")
}

fn request_error(status: StatusCode, code: &'static str, reason: &'static str) -> HttpResponse {
    tracing::warn!(event = "request_rejected", reason);
    json_error(status, code)
}

fn json_error_with_message(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> HttpResponse {
    HttpResponse::build(status).json(ErrorBody {
        schema_version: 1,
        error: ErrorDetail { code, message },
    })
}

fn mapped_error(error: &Error) -> HttpResponse {
    let text = error.to_string();
    let (status, reason) = if text.contains("san_not_allowed") {
        (StatusCode::FORBIDDEN, "san_not_authorized")
    } else if text.contains("idempotency_conflict") {
        (StatusCode::CONFLICT, "idempotency_conflict")
    } else if text.contains("san_required") {
        (StatusCode::UNPROCESSABLE_ENTITY, "san_required")
    } else if text.contains("unsupported_csr_profile") {
        (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_csr_profile")
    } else if text.contains("malformed_subject") {
        (StatusCode::BAD_REQUEST, "malformed_subject")
    } else if text.contains("malformed_csr") {
        (StatusCode::BAD_REQUEST, "malformed_csr")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "ca_not_ready")
    };
    tracing::warn!(event = "enrollment_denied", reason);
    json_error(status, reason)
}

struct InFlightGuard(Arc<AtomicUsize>);

struct DeadlineBody<B> {
    body: Pin<Box<B>>,
    deadline: Instant,
}

impl<B> MessageBody for DeadlineBody<B>
where
    B: MessageBody,
    B::Error: Into<Box<dyn std::error::Error>>,
{
    type Error = Box<dyn std::error::Error>;

    fn size(&self) -> actix_web::body::BodySize {
        self.body.as_ref().size()
    }

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<web::Bytes, Self::Error>>> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "absolute request deadline expired during response transmission",
            )))));
        }
        match self.body.as_mut().poll_next(context) {
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(bytes))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl InFlightGuard {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self(count)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ReadinessWatcher {
    stop_event: HANDLE,
    thread: thread::JoinHandle<()>,
}

impl ReadinessWatcher {
    fn start(
        authority: Arc<LoadedAuthority>,
        issuance: Arc<Mutex<()>>,
        ready: Arc<AtomicBool>,
        pending: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut watcher = DirectoryWatcher::register(&authority.state_dir).inspect_err(|_| {
            tracing::warn!(event = "watcher_failed", reason = "initial_registration");
        })?;
        let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if stop_event.is_null() {
            return Err(Error::new(
                ErrorClass::Http,
                "watcher stop event creation failed",
            ));
        }
        let stop_value = stop_event as usize;
        let handle = thread::spawn(move || {
            let stop_event = stop_value as HANDLE;
            let mut initial = true;
            let mut recovery_logged = false;
            loop {
                let event = if initial {
                    initial = false;
                    Ok(Some(WatchResult::Timeout))
                } else {
                    match watcher.wait_with_stop(stop_event, Duration::from_secs(60)) {
                        Ok(None) => break,
                        other => other,
                    }
                };
                pending.store(true, Ordering::Release);
                let reason = match &event {
                    Err(_) => "wait_failed",
                    Ok(Some(WatchResult::Overflow)) => "overflow",
                    Ok(Some(WatchResult::Changed)) => "state_change",
                    Ok(Some(WatchResult::Timeout)) | Ok(None) => "periodic_validation",
                };
                set_readiness(&ready, false, reason);
                if (event.is_err() || matches!(event, Ok(Some(WatchResult::Overflow))))
                    && !replace_watcher(
                        &mut watcher,
                        &authority.state_dir,
                        if event.is_err() {
                            "wait_failed"
                        } else {
                            "overflow"
                        },
                    )
                {
                    continue;
                }
                if let Ok(_guard) = issuance.lock() {
                    loop {
                        if crate::authority::revalidate(&authority).is_err() {
                            set_readiness(&ready, false, "state_invalid");
                            break;
                        }
                        match watcher.wait(Duration::ZERO) {
                            Ok(WatchResult::Timeout) => {
                                pending.store(false, Ordering::Release);
                                set_readiness(&ready, true, "state_validated");
                                if !recovery_logged
                                    && let Ok((issuances, reservations, audits)) =
                                        crate::authority::recovery_counts(&authority.state_dir)
                                {
                                    tracing::info!(
                                        event = "recovery_completed",
                                        authority_id = authority.authority.authority_id,
                                        completed_issuances = issuances,
                                        serial_reservations = reservations,
                                        audit_records = audits
                                    );
                                    recovery_logged = true;
                                }
                                break;
                            }
                            Ok(WatchResult::Changed) => continue,
                            Ok(WatchResult::Overflow) => {
                                if !replace_watcher(
                                    &mut watcher,
                                    &authority.state_dir,
                                    "drain_overflow",
                                ) {
                                    break;
                                }
                            }
                            Err(_) => {
                                if !replace_watcher(
                                    &mut watcher,
                                    &authority.state_dir,
                                    "drain_failed",
                                ) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        Ok(Self {
            stop_event,
            thread: handle,
        })
    }

    fn stop_and_join(self) -> Result<()> {
        if unsafe { SetEvent(self.stop_event) } == 0 {
            return Err(Error::new(ErrorClass::Http, "watcher stop signal failed"));
        }
        let result = self
            .thread
            .join()
            .map_err(|_| Error::new(ErrorClass::Http, "readiness watcher panicked"));
        unsafe { CloseHandle(self.stop_event) };
        result
    }
}

fn set_readiness(ready: &AtomicBool, value: bool, reason: &'static str) -> bool {
    if ready.swap(value, Ordering::AcqRel) == value {
        return false;
    }
    tracing::info!(event = "readiness_changed", ready = value, reason);
    true
}

fn replace_watcher(watcher: &mut DirectoryWatcher, state_dir: &Path, reason: &'static str) -> bool {
    let Some(replacement) = attempt_watcher_replacement(reason, || {
        DirectoryWatcher::register_replacement(state_dir).ok()
    }) else {
        return false;
    };
    *watcher = replacement;
    true
}

fn attempt_watcher_replacement<T, F>(reason: &'static str, register: F) -> Option<T>
where
    F: FnOnce() -> Option<T>,
{
    tracing::warn!(event = "watcher_failed", reason);
    let replacement = register()?;
    tracing::info!(event = "watcher_replaced", reason);
    Some(replacement)
}

struct RateLimiter {
    sources: HashMap<IpAddr, (u8, Instant)>,
    global: (u8, Instant),
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            sources: HashMap::new(),
            global: (10, Instant::now()),
        }
    }

    fn allow(&mut self, source: IpAddr) -> bool {
        self.allow_at(source, Instant::now())
    }

    fn allow_at(&mut self, source: IpAddr, now: Instant) -> bool {
        refill(&mut self.global, now, Duration::from_secs(1), 10);
        let entry = self.sources.entry(source).or_insert((3, now));
        refill(entry, now, Duration::from_secs(6), 3);
        if self.global.0 == 0 || entry.0 == 0 {
            return false;
        }
        self.global.0 -= 1;
        entry.0 -= 1;
        if self.sources.len() > 1024 {
            self.sources
                .retain(|_, value| now.duration_since(value.1) < Duration::from_secs(60));
        }
        true
    }
}

fn refill(bucket: &mut (u8, Instant), now: Instant, interval: Duration, cap: u8) {
    let elapsed = now.duration_since(bucket.1);
    let intervals = elapsed.as_nanos() / interval.as_nanos();
    if intervals == 0 {
        return;
    }
    let added = intervals.min(u128::from(cap)) as u8;
    bucket.0 = bucket.0.saturating_add(added).min(cap);
    let remainder = elapsed.as_nanos() % interval.as_nanos();
    bucket.1 = now
        .checked_sub(Duration::from_nanos(remainder as u64))
        .unwrap_or(now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|error| panic!("{error}"))
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureWriter(Arc::clone(&self.0))
        }
    }

    fn capture_events(action: impl FnOnce()) -> String {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(Capture(Arc::clone(&bytes)))
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .compact()
            .finish();
        tracing::subscriber::with_default(subscriber, action);
        String::from_utf8(
            bytes
                .lock()
                .unwrap_or_else(|error| panic!("{error}"))
                .clone(),
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn shutdown_events_describe_only_successful_graceful_shutdown() {
        let output = capture_events(|| {
            tracing::info!(event = "server_shutdown_started");
            assert!(
                finish_server_lifecycle(Ok(()), || {
                    tracing::info!(event = "watcher_stopped");
                    Ok(())
                })
                .is_ok()
            );
        });
        let started = output
            .find("event=\"server_shutdown_started\"")
            .unwrap_or_else(|| panic!("{output}"));
        let watcher = output
            .find("event=\"watcher_stopped\"")
            .unwrap_or_else(|| panic!("{output}"));
        let completed = output
            .find("event=\"server_shutdown_completed\"")
            .unwrap_or_else(|| panic!("{output}"));
        assert!(started < watcher && watcher < completed);

        let output = capture_events(|| {
            let result = finish_server_lifecycle(
                Err(Error::new(ErrorClass::Http, "injected startup failure")),
                || Ok(()),
            );
            assert!(result.is_err());
        });
        assert!(!output.contains("server_shutdown_started"));
        assert!(!output.contains("server_shutdown_completed"));

        let output = capture_events(|| {
            tracing::info!(event = "server_shutdown_started");
            let result = finish_server_lifecycle(Ok(()), || {
                Err(Error::new(ErrorClass::Http, "injected watcher failure"))
            });
            assert!(result.is_err());
        });
        assert!(output.contains("server_shutdown_started"));
        assert!(!output.contains("server_shutdown_completed"));
    }

    #[test]
    fn readiness_and_watcher_events_are_transition_bound_and_paired() {
        let ready = AtomicBool::new(false);
        let output = capture_events(|| {
            assert!(!set_readiness(&ready, false, "state_invalid"));
            assert!(set_readiness(&ready, true, "state_validated"));
            assert!(!set_readiness(&ready, true, "state_validated"));
            assert!(set_readiness(&ready, false, "state_invalid"));
            assert!(!set_readiness(&ready, false, "state_invalid"));

            assert_eq!(
                attempt_watcher_replacement("overflow", || Some(1_u8)),
                Some(1)
            );
            assert_eq!(
                attempt_watcher_replacement("drain_failed", || Some(2_u8)),
                Some(2)
            );
            assert_eq!(
                attempt_watcher_replacement::<u8, _>("wait_failed", || None),
                None
            );
        });
        assert_eq!(output.matches("event=\"readiness_changed\"").count(), 2);
        assert_eq!(output.matches("event=\"watcher_failed\"").count(), 3);
        assert_eq!(output.matches("event=\"watcher_replaced\"").count(), 2);
        assert_eq!(output.matches("reason=\"state_invalid\"").count(), 1);
        assert_eq!(output.matches("reason=\"overflow\"").count(), 2);
        assert_eq!(output.matches("reason=\"drain_failed\"").count(), 2);
        assert_eq!(output.matches("reason=\"wait_failed\"").count(), 1);
    }

    #[test]
    fn rate_limiter_refills_incrementally_and_caps_bursts() {
        let start = Instant::now();
        let source = IpAddr::from([127, 0, 0, 1]);
        let mut limiter = RateLimiter {
            sources: HashMap::new(),
            global: (10, start),
        };
        assert!(limiter.allow_at(source, start));
        assert!(limiter.allow_at(source, start));
        assert!(limiter.allow_at(source, start));
        assert!(!limiter.allow_at(source, start + Duration::from_secs(5)));
        assert!(limiter.allow_at(source, start + Duration::from_secs(6)));
        assert!(!limiter.allow_at(source, start + Duration::from_secs(11)));
        assert!(limiter.allow_at(source, start + Duration::from_secs(12)));
        assert_eq!(limiter.sources[&source].0, 0);
        assert!(limiter.global.0 <= 10);

        let mut global = RateLimiter {
            sources: HashMap::new(),
            global: (0, start),
        };
        assert!(!global.allow_at(source, start + Duration::from_millis(999)));
        assert!(global.allow_at(source, start + Duration::from_secs(1)));
        assert!(!global.allow_at(source, start + Duration::from_millis(1_999)));
        assert!(global.allow_at(source, start + Duration::from_secs(2)));
        global.allow_at(source, start + Duration::from_secs(100));
        assert!(global.global.0 <= 10);

        let mut source_bucket = (3, start);
        refill(
            &mut source_bucket,
            start + Duration::from_millis(6_500),
            Duration::from_secs(6),
            3,
        );
        assert_eq!(source_bucket.1, start + Duration::from_secs(6));
        source_bucket.0 -= 1;
        refill(
            &mut source_bucket,
            start + Duration::from_millis(11_999),
            Duration::from_secs(6),
            3,
        );
        assert_eq!(source_bucket.0, 2);
        refill(
            &mut source_bucket,
            start + Duration::from_secs(12),
            Duration::from_secs(6),
            3,
        );
        assert_eq!(source_bucket.0, 3);

        let mut global_bucket = (10, start);
        refill(
            &mut global_bucket,
            start + Duration::from_millis(1_500),
            Duration::from_secs(1),
            10,
        );
        assert_eq!(global_bucket.1, start + Duration::from_secs(1));
        global_bucket.0 -= 1;
        refill(
            &mut global_bucket,
            start + Duration::from_millis(1_999),
            Duration::from_secs(1),
            10,
        );
        assert_eq!(global_bucket.0, 9);
        refill(
            &mut global_bucket,
            start + Duration::from_secs(2),
            Duration::from_secs(1),
            10,
        );
        assert_eq!(global_bucket.0, 10);
    }

    #[test]
    fn public_json_contracts_are_exact() {
        actix_web::rt::System::new().block_on(async {
            let live = livez().await;
            assert_eq!(
                to_bytes(live.into_body())
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
                br#"{"live":true,"schema_version":1}"#.as_slice()
            );
            let error = json_error(StatusCode::CONFLICT, "idempotency_conflict");
            assert_eq!(
                to_bytes(error.into_body())
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
                br#"{"schema_version":1,"error":{"code":"idempotency_conflict","message":"request rejected"}}"#
                    .as_slice()
            );
            let missing = not_found();
            assert_eq!(
                to_bytes(missing.into_body())
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
                br#"{"schema_version":1,"error":{"code":"certificate_not_found","message":"certificate not found"}}"#
                    .as_slice()
            );
            let ready = readiness_response(true);
            assert_eq!(
                to_bytes(ready.into_body())
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
                br#"{"ready":true,"schema_version":1}"#.as_slice()
            );
            let metadata = metadata_response("authority");
            assert_eq!(
                to_bytes(metadata.into_body())
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
                br#"{"authority_id":"authority","certificates":"/v1/certificates","root":"/v1/ca/root","schema_version":1}"#
                    .as_slice()
            );
            let status = status_response(
                r#"{"schema_version":1,"issuance_id":"id","status":"valid"}"#.to_owned(),
            );
            assert_eq!(
                to_bytes(status.into_body())
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
                br#"{"schema_version":1,"issuance_id":"id","status":"valid"}"#.as_slice()
            );
            for (text, code, status) in [
                (
                    "san_not_allowed",
                    "san_not_authorized",
                    StatusCode::FORBIDDEN,
                ),
                (
                    "idempotency_conflict",
                    "idempotency_conflict",
                    StatusCode::CONFLICT,
                ),
                (
                    "san_required",
                    "san_required",
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                (
                    "unsupported_csr_profile",
                    "unsupported_csr_profile",
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                (
                    "malformed_subject",
                    "malformed_subject",
                    StatusCode::BAD_REQUEST,
                ),
                (
                    "malformed_csr",
                    "malformed_csr",
                    StatusCode::BAD_REQUEST,
                ),
            ] {
                let response = mapped_error(&Error::new(ErrorClass::Validation, text));
                assert_eq!(response.status(), status);
                let expected = format!(
                    r#"{{"schema_version":1,"error":{{"code":"{code}","message":"request rejected"}}}}"#
                );
                assert_eq!(
                    to_bytes(response.into_body())
                        .await
                        .unwrap_or_else(|error| panic!("{error}")),
                    expected.as_bytes()
                );
            }
        });
    }

    #[test]
    fn accept_deadline_bounds_headers_body_queue_and_releases_permits() {
        let (port, server, server_thread, blocking_state) = deadline_server();

        let start = Instant::now();
        let mut slow_header =
            TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|error| panic!("{error}"));
        slow_header
            .write_all(b"GET /fast HTTP/1.1\r\nHost:")
            .unwrap_or_else(|error| panic!("{error}"));
        slow_header
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap_or_else(|error| panic!("{error}"));
        let mut response = Vec::new();
        let _ = slow_header.read_to_end(&mut response);
        assert!(start.elapsed() < Duration::from_secs(2));

        let start = Instant::now();
        let mut slow_body =
            TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|error| panic!("{error}"));
        slow_body
            .write_all(b"POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\na")
            .unwrap_or_else(|error| panic!("{error}"));
        slow_body
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap_or_else(|error| panic!("{error}"));
        response.clear();
        slow_body
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(
            response.starts_with(b"HTTP/1.1 408") || response.starts_with(b"HTTP/1.1 503"),
            "unexpected slow-body response: {}",
            String::from_utf8_lossy(&response)
        );

        let response = raw_request(port, b"GET /delay HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(
            response.starts_with(b"HTTP/1.1 408") || response.starts_with(b"HTTP/1.1 503"),
            "unexpected delayed response: {}",
            String::from_utf8_lossy(&response)
        );
        let fast_start = Instant::now();
        let response = raw_request(port, b"GET /fast HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "unexpected recovery response: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(fast_start.elapsed() < Duration::from_millis(150));
        let mut slow_reader =
            TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|error| panic!("{error}"));
        slow_reader
            .write_all(b"GET /slow-response HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap_or_else(|error| panic!("{error}"));
        let mut second_slow_reader =
            TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|error| panic!("{error}"));
        second_slow_reader
            .write_all(b"GET /slow-response HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap_or_else(|error| panic!("{error}"));
        let start = Instant::now();
        thread::sleep(Duration::from_millis(500));
        let recovery = raw_request(port, b"GET /fast HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(recovery.starts_with(b"HTTP/1.1 200"));
        slow_reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|error| panic!("{error}"));
        let mut response = Vec::new();
        slow_reader
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("{error}"));
        second_slow_reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|error| panic!("{error}"));
        let mut second_response = Vec::new();
        second_slow_reader
            .read_to_end(&mut second_response)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!response.is_empty());
        assert!(!second_response.is_empty());

        let hold = thread::spawn(move || {
            raw_request(
                port,
                b"GET /blocking/hold HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
        });
        thread::sleep(Duration::from_millis(30));
        let queued = thread::spawn(move || {
            raw_request(
                port,
                b"GET /blocking/queued HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
        });
        thread::sleep(Duration::from_millis(280));
        assert_eq!(blocking_state.in_flight.load(Ordering::Acquire), 2);
        assert!(blocking_state.admission.try_acquire().is_err());
        assert!(blocking_state.blocking.try_acquire().is_err());
        let _ = hold
            .join()
            .unwrap_or_else(|_| panic!("hold client panicked"));
        let _ = queued
            .join()
            .unwrap_or_else(|_| panic!("queued client panicked"));
        thread::sleep(Duration::from_millis(400));
        assert_eq!(blocking_state.in_flight.load(Ordering::Acquire), 0);
        assert!(blocking_state.admission.try_acquire().is_ok());
        assert!(blocking_state.blocking.try_acquire().is_ok());
        assert_eq!(blocking_state.completed.load(Ordering::Acquire), 2);

        actix_web::rt::System::new().block_on(server.stop(true));
        server_thread
            .join()
            .unwrap_or_else(|_| panic!("deadline test server panicked"));
    }

    #[test]
    fn routing_contract_intercepts_all_method_mismatches() {
        actix_web::rt::System::new().block_on(async {
            let app = actix_web::test::init_service(App::new().service(api_scope())).await;
            for path in [
                "/livez",
                "/readyz",
                "/v1/ca",
                "/v1/ca/root",
                "/v1/certificates/0123456789abcdef0123456789abcdef",
                "/v1/certificates/0123456789abcdef0123456789abcdef/status",
            ] {
                assert_contract_response(
                    actix_web::test::call_service(
                        &app,
                        actix_web::test::TestRequest::post().uri(path).to_request(),
                    )
                    .await,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                )
                .await;
            }
            assert_contract_response(
                actix_web::test::call_service(
                    &app,
                    actix_web::test::TestRequest::get()
                        .uri("/v1/certificates")
                        .to_request(),
                )
                .await,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            )
            .await;
            for method in [actix_web::http::Method::GET, actix_web::http::Method::POST] {
                assert_contract_response(
                    actix_web::test::call_service(
                        &app,
                        actix_web::test::TestRequest::default()
                            .method(method)
                            .uri("/unknown")
                            .to_request(),
                    )
                    .await,
                    StatusCode::NOT_FOUND,
                    "certificate_not_found",
                )
                .await;
            }
            assert_contract_response(
                actix_web::test::call_service(
                    &app,
                    actix_web::test::TestRequest::default()
                        .method(actix_web::http::Method::DELETE)
                        .uri("/unknown")
                        .to_request(),
                )
                .await,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            )
            .await;
        });
    }

    async fn assert_contract_response<B>(
        response: ServiceResponse<B>,
        status: StatusCode,
        code: &str,
    ) where
        B: MessageBody,
        B::Error: std::fmt::Debug,
    {
        assert_eq!(response.status(), status);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = actix_web::test::read_body(response).await;
        let message = if code == "certificate_not_found" {
            "certificate not found"
        } else {
            "request rejected"
        };
        assert_eq!(
            body,
            format!(r#"{{"schema_version":1,"error":{{"code":"{code}","message":"{message}"}}}}"#)
                .as_bytes()
        );
    }

    fn deadline_server() -> (
        u16,
        actix_web::dev::ServerHandle,
        thread::JoinHandle<()>,
        Arc<BlockingTestState>,
    ) {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).unwrap_or_else(|error| panic!("{error}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"))
            .port();
        let blocking_state = Arc::new(BlockingTestState::new());
        let server_state = web::Data::from(Arc::clone(&blocking_state));
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            actix_web::rt::System::new().block_on(async move {
                let server = HttpServer::new(move || {
                    App::new()
                        .app_data(server_state.clone())
                        .app_data(web::Data::new(DeadlineConfig(Duration::from_millis(250))))
                        .wrap(actix_web::middleware::from_fn(protocol_middleware))
                        .route(
                            "/fast",
                            web::get().to(|| async { HttpResponse::Ok().finish() }),
                        )
                        .route(
                            "/delay",
                            web::get().to(|| async {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                HttpResponse::Ok().finish()
                            }),
                        )
                        .route(
                            "/body",
                            web::post()
                                .to(|_: Pkcs10Request| async { HttpResponse::Ok().finish() }),
                        )
                        .route(
                            "/slow-response",
                            web::get().to(|| async {
                                HttpResponse::Ok().body(vec![0_u8; 64 * 1024 * 1024])
                            }),
                        )
                        .route("/blocking/{kind}", web::get().to(blocking_test))
                })
                .workers(1)
                .max_connections(2)
                .client_request_timeout(Duration::from_secs(1))
                .keep_alive(KeepAlive::Disabled)
                .on_connect(|io, extensions| {
                    register_connection_deadline(io, extensions, Duration::from_millis(250));
                })
                .listen(listener)
                .unwrap_or_else(|error| panic!("{error}"))
                .run();
                sender
                    .send(server.handle())
                    .unwrap_or_else(|error| panic!("{error}"));
                server.await.unwrap_or_else(|error| panic!("{error}"));
            });
        });
        let handle = receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("{error}"));
        (port, handle, thread, blocking_state)
    }

    fn raw_request(port: u16, request: &[u8]) -> Vec<u8> {
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|error| panic!("{error}"));
        stream
            .write_all(request)
            .unwrap_or_else(|error| panic!("{error}"));
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap_or_else(|error| panic!("{error}"));
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("{error}"));
        response
    }

    struct BlockingTestState {
        admission: Arc<Semaphore>,
        blocking: Arc<Semaphore>,
        in_flight: Arc<AtomicUsize>,
        completed: AtomicUsize,
        gate: Mutex<()>,
    }

    impl BlockingTestState {
        fn new() -> Self {
            Self {
                admission: Arc::new(Semaphore::new(2)),
                blocking: Arc::new(Semaphore::new(2)),
                in_flight: Arc::new(AtomicUsize::new(0)),
                completed: AtomicUsize::new(0),
                gate: Mutex::new(()),
            }
        }
    }

    async fn blocking_test(
        request: HttpRequest,
        path: web::Path<String>,
        state: web::Data<BlockingTestState>,
    ) -> HttpResponse {
        let deadline = request.extensions().get::<RequestDeadline>().map_or_else(
            || Instant::now() + Duration::from_millis(200),
            |value| value.processing,
        );
        let admission = Arc::clone(&state.admission)
            .try_acquire_owned()
            .unwrap_or_else(|error| panic!("{error}"));
        let blocking = Arc::clone(&state.blocking)
            .try_acquire_owned()
            .unwrap_or_else(|error| panic!("{error}"));
        let state = state.into_inner();
        let kind = path.into_inner();
        let job = actix_web::rt::task::spawn_blocking(move || {
            let _guard = InFlightGuard::new(Arc::clone(&state.in_flight));
            let _permits = (admission, blocking);
            let _gate = state.gate.lock().unwrap_or_else(|error| panic!("{error}"));
            if kind == "hold" {
                thread::sleep(Duration::from_millis(500));
            }
            state.completed.fetch_add(1, Ordering::AcqRel);
        });
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), job).await {
            Ok(_) => HttpResponse::Ok().finish(),
            Err(_) => json_error(StatusCode::SERVICE_UNAVAILABLE, "busy"),
        }
    }
}
