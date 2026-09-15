//! Bounded HTTP/1.1 parsing, routing, rate limiting, admission, and shutdown.

use crate::authority::{LoadedAuthority, certificate_bytes, certificate_status, issue};
use crate::cli::ServeArgs;
use crate::csr::parse_and_authorize;
use crate::error::{Error, ErrorClass, Result};
use crate::policy::warning_text;
use crate::state::{DirectoryWatcher, WatchResult};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_REQUEST_LINE: usize = 2048;
const MAX_HEADERS_BYTES: usize = 16_384;
const MAX_HEADERS: usize = 32;
const MAX_HEADER_NAME: usize = 64;
const MAX_HEADER_VALUE: usize = 4096;
const MAX_RESPONSE: usize = 131_072;
const REQUEST_LIFETIME: Duration = Duration::from_secs(10);

pub fn serve(args: ServeArgs, loaded: LoadedAuthority) -> Result<()> {
    eprint!("{}", warning_text());
    if !args.listen.ip().is_loopback() {
        eprintln!(
            "WARNING: non-loopback binding and firewall rules reduce reachability only; they do not authenticate callers."
        );
    }
    let listener = TcpListener::bind(args.listen)
        .map_err(|error| Error::new(ErrorClass::Http, format!("HTTP bind failed: {error}")))?;
    listener.set_nonblocking(true).map_err(|error| {
        Error::new(
            ErrorClass::Http,
            format!("nonblocking setup failed: {error}"),
        )
    })?;
    let shutdown = Arc::new(AtomicBool::new(false));
    install_console_handler(Arc::clone(&shutdown))?;
    let permits = Arc::new(PermitPool::new(args.max_connections as usize));
    let workers = usize::from(args.max_connections.min(8));
    let queue_capacity = args.max_connections as usize - workers;
    let queue = Arc::new(SocketQueue::new(queue_capacity));
    let authority = Arc::new(loaded);
    let policy = Arc::new(args.clone());
    let limiter = Arc::new(Mutex::new(RateLimiter::new(
        args.per_source_per_minute,
        args.global_per_minute,
    )));
    let issuance_mutex = Arc::new(Mutex::new(()));
    let readiness = Arc::new(AtomicBool::new(false));
    let mut watcher = DirectoryWatcher::register(&authority.state_dir)?;
    let initially_consistent = issuance_mutex.lock().ok().is_some_and(|_guard| {
        scan_until_quiescent(
            &mut watcher,
            &shutdown,
            || crate::authority::revalidate(&authority).is_ok(),
            || DirectoryWatcher::register_replacement(&authority.state_dir),
        )
    });
    if !initially_consistent {
        return Err(Error::new(
            ErrorClass::State,
            "initial watched state scan did not reach a consistent quiescent point",
        ));
    }
    readiness.store(true, Ordering::Release);
    let watcher_handle = {
        let authority = Arc::clone(&authority);
        let issuance_mutex = Arc::clone(&issuance_mutex);
        let readiness = Arc::clone(&readiness);
        let shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            readiness_watch_loop(watcher, &authority, &issuance_mutex, &readiness, &shutdown);
        })
    };
    let mut worker_handles = Vec::new();
    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let authority = Arc::clone(&authority);
        let policy = Arc::clone(&policy);
        let limiter = Arc::clone(&limiter);
        let issuance_mutex = Arc::clone(&issuance_mutex);
        let shutdown = Arc::clone(&shutdown);
        let readiness = Arc::clone(&readiness);
        worker_handles.push(thread::spawn(move || {
            while let Some(socket) = queue.pop(&shutdown) {
                let _ = handle_connection(
                    socket,
                    &authority,
                    &policy,
                    &limiter,
                    &issuance_mutex,
                    &readiness,
                );
            }
        }));
    }
    while !shutdown.load(Ordering::Acquire) {
        let Some(permit) = permits.try_acquire() else {
            thread::park_timeout(Duration::from_millis(25));
            continue;
        };
        match listener.accept() {
            Ok((stream, source)) => {
                let socket = AdmittedSocket {
                    stream,
                    source: source.ip(),
                    deadline: Instant::now() + REQUEST_LIFETIME,
                    _permit: permit,
                };
                if !queue.push(socket, &shutdown) {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                drop(permit);
                thread::park_timeout(Duration::from_millis(25));
            }
            Err(error) => {
                shutdown.store(true, Ordering::Release);
                queue.close();
                return Err(Error::new(
                    ErrorClass::Http,
                    format!("HTTP accept failed: {error}"),
                ));
            }
        }
    }
    shutdown.store(true, Ordering::Release);
    queue.close();
    for handle in worker_handles {
        handle
            .join()
            .map_err(|_| Error::new(ErrorClass::Http, "HTTP worker panicked"))?;
    }
    watcher_handle
        .join()
        .map_err(|_| Error::new(ErrorClass::Http, "readiness watcher panicked"))?;
    Ok(())
}

fn readiness_watch_loop(
    mut watcher: DirectoryWatcher,
    authority: &LoadedAuthority,
    issuance_mutex: &Mutex<()>,
    readiness: &AtomicBool,
    shutdown: &AtomicBool,
) {
    let mut last_kat = Instant::now();
    while !shutdown.load(Ordering::Acquire) {
        let result = watcher.wait(Duration::from_millis(250));
        let recurring = last_kat.elapsed() >= Duration::from_secs(60);
        if !recurring && matches!(result, Ok(WatchResult::Timeout)) {
            continue;
        }
        readiness.store(false, Ordering::Release);
        if result.is_err() || matches!(result, Ok(WatchResult::Overflow)) {
            match DirectoryWatcher::register_replacement(&authority.state_dir) {
                Ok(replacement) => watcher = replacement,
                Err(_) => {
                    last_kat = Instant::now();
                    continue;
                }
            }
        }
        let consistent = issuance_mutex.lock().ok().is_some_and(|_guard| {
            scan_until_quiescent(
                &mut watcher,
                shutdown,
                || crate::authority::revalidate(authority).is_ok(),
                || DirectoryWatcher::register_replacement(&authority.state_dir),
            )
        });
        if consistent && !shutdown.load(Ordering::Acquire) {
            readiness.store(true, Ordering::Release);
        }
        last_kat = Instant::now();
    }
}

trait ChangeWatch {
    fn poll(&mut self, timeout: Duration) -> Result<WatchResult>;
}

impl ChangeWatch for DirectoryWatcher {
    fn poll(&mut self, timeout: Duration) -> Result<WatchResult> {
        self.wait(timeout)
    }
}

fn scan_until_quiescent<W, S, R>(
    watcher: &mut W,
    shutdown: &AtomicBool,
    mut scan: S,
    mut register: R,
) -> bool
where
    W: ChangeWatch,
    S: FnMut() -> bool,
    R: FnMut() -> Result<W>,
{
    loop {
        if shutdown.load(Ordering::Acquire) || !scan() {
            return false;
        }
        match watcher.poll(Duration::ZERO) {
            Ok(WatchResult::Timeout) => return true,
            Ok(WatchResult::Changed) => {}
            Ok(WatchResult::Overflow) | Err(_) => match register() {
                Ok(replacement) => *watcher = replacement,
                Err(_) => return false,
            },
        }
    }
}

fn handle_connection(
    mut socket: AdmittedSocket,
    authority: &LoadedAuthority,
    policy: &ServeArgs,
    limiter: &Mutex<RateLimiter>,
    issuance_mutex: &Mutex<()>,
    readiness: &AtomicBool,
) -> Result<()> {
    let deadline = socket.deadline;
    if Instant::now() >= deadline {
        return Err(Error::new(
            ErrorClass::Http,
            "accepted request expired before worker service",
        ));
    }
    let request = match read_request(&mut socket.stream, policy.max_request_body_bytes, deadline) {
        Ok(request) => request,
        Err(response) => return write_response(&mut socket.stream, response, deadline),
    };
    let response = route(
        request,
        socket.source,
        authority,
        policy,
        limiter,
        issuance_mutex,
        readiness,
    );
    write_response(&mut socket.stream, response, deadline)
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    extra_headers: Vec<(&'static str, String)>,
}

fn read_request(
    stream: &mut TcpStream,
    body_limit: usize,
    deadline: Instant,
) -> std::result::Result<Request, Response> {
    let mut bytes = Vec::with_capacity(4096);
    let header_end;
    loop {
        if Instant::now() >= deadline {
            return Err(error_response(400, "malformed_request", "request rejected"));
        }
        let mut chunk = [0; 1024];
        set_read_remaining(stream, deadline)?;
        let count = stream
            .read(&mut chunk)
            .map_err(|_| error_response(400, "malformed_request", "request rejected"))?;
        if count == 0 {
            return Err(error_response(400, "malformed_request", "request rejected"));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > MAX_HEADERS_BYTES + body_limit {
            return Err(error_response(413, "request_too_large", "request rejected"));
        }
        if let Some(position) = find(&bytes, b"\r\n\r\n") {
            header_end = position + 4;
            reject_raw_framing(&bytes[..header_end])?;
            break;
        }
        reject_raw_framing(&bytes)?;
        if bytes.len() > MAX_HEADERS_BYTES {
            return Err(error_response(413, "request_too_large", "request rejected"));
        }
    }
    let header_bytes = &bytes[..header_end];
    let request_line_end = find(header_bytes, b"\r\n")
        .ok_or_else(|| error_response(400, "malformed_request", "request rejected"))?;
    if request_line_end > MAX_REQUEST_LINE {
        return Err(error_response(413, "request_too_large", "request rejected"));
    }
    let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut parsed_headers);
    match parsed.parse(header_bytes) {
        Ok(httparse::Status::Complete(consumed)) if consumed == header_end => {}
        _ => return Err(error_response(400, "malformed_request", "request rejected")),
    }
    if parsed.version != Some(1) {
        return Err(error_response(400, "malformed_request", "request rejected"));
    }
    let method = parsed
        .method
        .ok_or_else(|| error_response(400, "malformed_request", "request rejected"))?
        .to_owned();
    let path = parsed
        .path
        .ok_or_else(|| error_response(400, "malformed_request", "request rejected"))?
        .to_owned();
    validate_target(&path)?;
    let mut headers = HashMap::new();
    for header in parsed.headers.iter() {
        if header.name.len() > MAX_HEADER_NAME || header.value.len() > MAX_HEADER_VALUE {
            return Err(error_response(413, "request_too_large", "request rejected"));
        }
        let name = header.name.to_ascii_lowercase();
        let value = std::str::from_utf8(header.value)
            .map_err(|_| error_response(400, "malformed_request", "request rejected"))?
            .trim()
            .to_owned();
        if headers.insert(name.clone(), value).is_some() {
            return Err(error_response(400, "malformed_request", "request rejected"));
        }
        if matches!(
            name.as_str(),
            "transfer-encoding" | "trailer" | "upgrade" | "expect" | "content-encoding"
        ) {
            return Err(error_response(400, "malformed_request", "request rejected"));
        }
    }
    if !headers.contains_key("host") {
        return Err(error_response(400, "malformed_request", "request rejected"));
    }
    let length = match headers.get("content-length") {
        Some(value) => {
            if value.is_empty()
                || value.len() > 1 && value.starts_with('0')
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(error_response(400, "malformed_request", "request rejected"));
            }
            value
                .parse::<usize>()
                .map_err(|_| error_response(400, "malformed_request", "request rejected"))?
        }
        None => 0,
    };
    if length > body_limit {
        return Err(error_response(413, "request_too_large", "request rejected"));
    }
    while bytes.len() < header_end + length {
        let remaining = header_end + length - bytes.len();
        let mut chunk = vec![0; remaining.min(1024)];
        set_read_remaining(stream, deadline)?;
        let count = stream
            .read(&mut chunk)
            .map_err(|_| error_response(400, "malformed_request", "request rejected"))?;
        if count == 0 {
            return Err(error_response(400, "malformed_request", "request rejected"));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    if bytes.len() != header_end + length {
        return Err(error_response(400, "malformed_request", "request rejected"));
    }
    Ok(Request {
        method,
        path,
        headers,
        body: bytes[header_end..].to_vec(),
    })
}

fn reject_raw_framing(bytes: &[u8]) -> std::result::Result<(), Response> {
    if bytes.contains(&0) {
        return Err(error_response(400, "malformed_request", "request rejected"));
    }
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r') {
            return Err(error_response(400, "malformed_request", "request rejected"));
        }
        if *byte == b'\r' && bytes.get(index + 1).is_some_and(|next| *next != b'\n') {
            return Err(error_response(400, "malformed_request", "request rejected"));
        }
    }
    if bytes
        .windows(3)
        .any(|window| window[0..2] == *b"\r\n" && matches!(window[2], b' ' | b'\t'))
    {
        return Err(error_response(400, "malformed_request", "request rejected"));
    }
    Ok(())
}

fn validate_target(path: &str) -> std::result::Result<(), Response> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("://")
        || path.contains('#')
        || path.contains('?')
        || path.contains('%')
        || path.contains('\\')
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(error_response(400, "malformed_request", "request rejected"));
    }
    Ok(())
}

fn route(
    request: Request,
    source: IpAddr,
    authority: &LoadedAuthority,
    policy: &ServeArgs,
    limiter: &Mutex<RateLimiter>,
    issuance_mutex: &Mutex<()>,
    readiness: &AtomicBool,
) -> Response {
    if request.path != "/livez" && request.path != "/readyz" && !readiness.load(Ordering::Acquire) {
        return error_response(503, "ca_not_ready", "request rejected");
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/livez") => json_response(200, json!({"schema_version":1,"live":true})),
        ("GET", "/readyz") => {
            if readiness.load(Ordering::Acquire) {
                json_response(200, json!({"schema_version":1,"ready":true}))
            } else {
                error_response(503, "ca_not_ready", "request rejected")
            }
        }
        ("GET", "/v1/ca") => json_response(
            200,
            json!({
                "schema_version":1,
                "authority_id": authority.authority.authority_id,
                "root":"/v1/ca/root",
                "certificates":"/v1/certificates"
            }),
        ),
        ("GET", "/v1/ca/root") => Response {
            status: 200,
            content_type: "application/pkix-cert",
            body: authority.root_der.clone(),
            extra_headers: Vec::new(),
        },
        ("POST", "/v1/certificates") => {
            enroll(request, source, authority, policy, limiter, issuance_mutex)
        }
        ("GET", path) if path.ends_with("/status") => {
            let id = path
                .strip_prefix("/v1/certificates/")
                .and_then(|value| value.strip_suffix("/status"));
            match id.and_then(|id| certificate_status(&authority.state_dir, id).ok().flatten()) {
                Some(body) => Response {
                    status: 200,
                    content_type: "application/json",
                    body: body.into_bytes(),
                    extra_headers: Vec::new(),
                },
                None => not_found(),
            }
        }
        ("GET", path) if path.starts_with("/v1/certificates/") => {
            let id = &path["/v1/certificates/".len()..];
            match certificate_bytes(&authority.state_dir, id).ok().flatten() {
                Some(body) => Response {
                    status: 200,
                    content_type: "application/pkix-cert",
                    body,
                    extra_headers: Vec::new(),
                },
                None => not_found(),
            }
        }
        ("GET", _) | ("POST", _) => not_found(),
        _ => error_response(405, "method_not_allowed", "request rejected"),
    }
}

fn enroll(
    request: Request,
    source: IpAddr,
    authority: &LoadedAuthority,
    policy: &ServeArgs,
    limiter: &Mutex<RateLimiter>,
    issuance_mutex: &Mutex<()>,
) -> Response {
    if request.headers.get("content-type").map(String::as_str) != Some("application/pkcs10") {
        return error_response(415, "unsupported_media_type", "request rejected");
    }
    let Some(idempotency) = request.headers.get("idempotency-key") else {
        return error_response(400, "invalid_idempotency_key", "request rejected");
    };
    if idempotency.len() != 32
        || !idempotency
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return error_response(400, "invalid_idempotency_key", "request rejected");
    }
    if !limiter
        .lock()
        .map(|mut value| value.allow(source))
        .unwrap_or(false)
    {
        return error_response(429, "rate_limited", "request rejected");
    }
    let parsed = match parse_and_authorize(&request.body, policy) {
        Ok(parsed) => parsed,
        Err(error) => return map_enrollment_error(&error),
    };
    let _guard = match issuance_mutex.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response(503, "ca_not_ready", "request rejected"),
    };
    match issue(
        authority,
        policy,
        &parsed,
        &request.body,
        idempotency,
        &source.to_string(),
    ) {
        Ok(issued) => Response {
            status: issued.status,
            content_type: "application/pkix-cert",
            body: issued.certificate,
            extra_headers: vec![("X-AziHSM-Issuance-Id", issued.issuance_id)],
        },
        Err(error) => map_enrollment_error(&error),
    }
}

fn map_enrollment_error(error: &Error) -> Response {
    let text = error.to_string();
    if text.contains("idempotency_conflict") {
        error_response(409, "idempotency_conflict", "request rejected")
    } else if text.contains("san_not_authorized") {
        error_response(403, "san_not_authorized", "request rejected")
    } else if text.contains("san_required") {
        error_response(422, "san_required", "request rejected")
    } else if text.contains("unsupported_csr_profile") {
        error_response(422, "unsupported_csr_profile", "request rejected")
    } else if text.contains("malformed_subject") {
        error_response(400, "malformed_subject", "request rejected")
    } else if text.contains("malformed_csr") {
        error_response(400, "malformed_csr", "request rejected")
    } else {
        error_response(503, "ca_not_ready", "request rejected")
    }
}

fn json_response(status: u16, value: serde_json::Value) -> Response {
    Response {
        status,
        content_type: "application/json",
        body: serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec()),
        extra_headers: Vec::new(),
    }
}

fn error_response(status: u16, code: &str, message: &str) -> Response {
    json_response(
        status,
        json!({"schema_version":1,"error":{"code":code,"message":message}}),
    )
}

fn not_found() -> Response {
    error_response(404, "certificate_not_found", "certificate not found")
}

fn write_response(stream: &mut TcpStream, response: Response, deadline: Instant) -> Result<()> {
    if response.body.len() > MAX_RESPONSE {
        return Err(Error::new(
            ErrorClass::Http,
            "response exceeds configured cap",
        ));
    }
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    );
    for (name, value) in response.extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(&value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    write_all_remaining(stream, head.as_bytes(), deadline)?;
    write_all_remaining(stream, &response.body, deadline)?;
    set_write_remaining(stream, deadline)?;
    stream
        .flush()
        .map_err(|error| Error::new(ErrorClass::Http, format!("HTTP flush failed: {error}")))
}

fn set_read_remaining(stream: &TcpStream, deadline: Instant) -> std::result::Result<(), Response> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| error_response(400, "malformed_request", "request rejected"))?;
    stream
        .set_read_timeout(Some(remaining.min(Duration::from_secs(5))))
        .map_err(|_| error_response(400, "malformed_request", "request rejected"))
}

fn set_write_remaining(stream: &TcpStream, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            Error::new(
                ErrorClass::Http,
                "absolute request deadline expired before response completed",
            )
        })?;
    stream
        .set_write_timeout(Some(remaining.min(Duration::from_secs(5))))
        .map_err(|error| Error::new(ErrorClass::Http, format!("write timeout failed: {error}")))
}

fn write_all_remaining(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        set_write_remaining(stream, deadline)?;
        let written = stream
            .write(bytes)
            .map_err(|error| Error::new(ErrorClass::Http, format!("HTTP write failed: {error}")))?;
        if written == 0 {
            return Err(Error::new(ErrorClass::Http, "HTTP write made no progress"));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct AdmittedSocket {
    stream: TcpStream,
    source: IpAddr,
    deadline: Instant,
    _permit: Permit,
}

struct PermitPool {
    available: AtomicUsize,
}

impl PermitPool {
    fn new(count: usize) -> Self {
        Self {
            available: AtomicUsize::new(count),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<Permit> {
        self.available
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_sub(1)
            })
            .ok()
            .map(|_| Permit(Arc::clone(self)))
    }
}

struct Permit(Arc<PermitPool>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.available.fetch_add(1, Ordering::Release);
    }
}

struct SocketQueue {
    state: Mutex<QueueState>,
    available: Condvar,
    capacity: usize,
}

struct QueueState {
    sockets: VecDeque<AdmittedSocket>,
    closed: bool,
}

impl SocketQueue {
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(QueueState {
                sockets: VecDeque::new(),
                closed: false,
            }),
            available: Condvar::new(),
            capacity: capacity.max(1),
        }
    }

    fn push(&self, socket: AdmittedSocket, shutdown: &AtomicBool) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };
        while state.sockets.len() >= self.capacity
            && !state.closed
            && !shutdown.load(Ordering::Acquire)
        {
            state = match self
                .available
                .wait_timeout(state, Duration::from_millis(25))
            {
                Ok((state, _)) => state,
                Err(_) => return false,
            };
        }
        if state.closed || shutdown.load(Ordering::Acquire) {
            return false;
        }
        state.sockets.push_back(socket);
        self.available.notify_one();
        true
    }

    fn pop(&self, shutdown: &AtomicBool) -> Option<AdmittedSocket> {
        let mut state = self.state.lock().ok()?;
        loop {
            if let Some(socket) = state.sockets.pop_front() {
                self.available.notify_one();
                return Some(socket);
            }
            if state.closed || shutdown.load(Ordering::Acquire) {
                return None;
            }
            state = self.available.wait(state).ok()?;
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.sockets.clear();
            self.available.notify_all();
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

struct RateLimiter {
    sources: HashMap<IpAddr, Bucket>,
    source_refill: f64,
    global_refill: f64,
    global: Bucket,
}

impl RateLimiter {
    fn new(source_per_minute: u16, global_per_minute: u16) -> Self {
        Self {
            sources: HashMap::new(),
            source_refill: f64::from(source_per_minute) / 60.0,
            global_refill: f64::from(global_per_minute) / 60.0,
            global: Bucket {
                tokens: 10.0,
                updated: Instant::now(),
            },
        }
    }

    fn allow(&mut self, source: IpAddr) -> bool {
        let now = Instant::now();
        refill(&mut self.global, self.global_refill, 10.0, now);
        if self.global.tokens < 1.0 {
            return false;
        }
        if self.sources.len() >= 1024 && !self.sources.contains_key(&source) {
            if let Some(oldest) = self
                .sources
                .iter()
                .min_by_key(|(_, bucket)| bucket.updated)
                .map(|(address, _)| *address)
            {
                self.sources.remove(&oldest);
            }
        }
        let bucket = self.sources.entry(source).or_insert(Bucket {
            tokens: 3.0,
            updated: now,
        });
        refill(bucket, self.source_refill, 3.0, now);
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        self.global.tokens -= 1.0;
        true
    }
}

fn refill(bucket: &mut Bucket, refill_per_second: f64, burst: f64, now: Instant) {
    let elapsed = now.duration_since(bucket.updated).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * refill_per_second).min(burst);
    bucket.updated = now;
}

fn install_console_handler(shutdown: Arc<AtomicBool>) -> Result<()> {
    static SHUTDOWN: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);
    unsafe extern "system" fn handler(_: u32) -> i32 {
        if let Ok(guard) = SHUTDOWN.lock()
            && let Some(flag) = guard.as_ref()
        {
            flag.store(true, Ordering::Release);
            return 1;
        }
        0
    }
    *SHUTDOWN
        .lock()
        .map_err(|_| Error::new(ErrorClass::Http, "console handler mutex poisoned"))? =
        Some(shutdown);
    // SAFETY: the handler has static lifetime and accesses only synchronized state.
    if unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(handler), 1) } == 0
    {
        return Err(Error::new(ErrorClass::Http, "SetConsoleCtrlHandler failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    struct FakeWatch {
        results: VecDeque<std::result::Result<WatchResult, Error>>,
    }

    impl ChangeWatch for FakeWatch {
        fn poll(&mut self, _: Duration) -> Result<WatchResult> {
            self.results.pop_front().unwrap_or(Ok(WatchResult::Timeout))
        }
    }

    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let client = TcpStream::connect(address).unwrap_or_else(|error| panic!("{error}"));
        let (server, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        (client, server)
    }

    #[test]
    fn permit_pool_never_exceeds_bound() {
        for maximum in 1..=64 {
            let pool = Arc::new(PermitPool::new(maximum));
            let permits: Vec<_> = (0..maximum).map(|_| pool.try_acquire()).collect();
            assert!(permits.iter().all(Option::is_some));
            assert!(pool.try_acquire().is_none());
        }
    }

    #[test]
    fn raw_parser_rejects_bare_lf_and_obs_fold() {
        assert!(reject_raw_framing(b"GET / HTTP/1.1\n").is_err());
        assert!(reject_raw_framing(b"GET / HTTP/1.1\r\n folded").is_err());
    }

    #[test]
    fn not_found_shape_is_constant() {
        assert_eq!(not_found().body, not_found().body);
    }

    #[test]
    fn absolute_deadline_rejects_slow_header_trickle() {
        let (mut client, mut server) = socket_pair();
        let writer = thread::spawn(move || {
            for byte in b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n" {
                if client.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(35));
            }
        });
        let started = Instant::now();
        assert!(read_request(&mut server, 1024, started + Duration::from_millis(150)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = server.shutdown(Shutdown::Both);
        writer.join().unwrap_or_else(|_| panic!("writer panicked"));
    }

    #[test]
    fn absolute_deadline_rejects_slow_body_trickle() {
        let (mut client, mut server) = socket_pair();
        let writer = thread::spawn(move || {
            let _ = client.write_all(
                b"POST /v1/certificates HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\n",
            );
            for byte in b"12345678" {
                if client.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(35));
            }
        });
        let started = Instant::now();
        assert!(read_request(&mut server, 1024, started + Duration::from_millis(150)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = server.shutdown(Shutdown::Both);
        writer.join().unwrap_or_else(|_| panic!("writer panicked"));
    }

    #[test]
    fn expired_response_deadline_releases_the_connection() {
        let (_client, mut server) = socket_pair();
        let started = Instant::now();
        let result = write_response(
            &mut server,
            json_response(200, json!({"schema_version":1,"live":true})),
            started,
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn queued_socket_keeps_accept_deadline_and_releases_permit() {
        let (client, server) = socket_pair();
        let pool = Arc::new(PermitPool::new(1));
        let permit = pool
            .try_acquire()
            .unwrap_or_else(|| panic!("permit unavailable"));
        let queue = SocketQueue::new(1);
        let shutdown = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_millis(80);
        assert!(
            queue.push(
                AdmittedSocket {
                    stream: server,
                    source: "127.0.0.1"
                        .parse()
                        .unwrap_or_else(|error| panic!("{error}")),
                    deadline,
                    _permit: permit,
                },
                &shutdown,
            )
        );
        thread::sleep(Duration::from_millis(120));
        let admitted = queue
            .pop(&shutdown)
            .unwrap_or_else(|| panic!("queued socket missing"));
        assert!(Instant::now() >= admitted.deadline);
        drop(admitted);
        drop(client);
        assert!(pool.try_acquire().is_some());
    }

    #[test]
    fn queue_delay_cannot_reset_request_budget() {
        let (mut client, mut server) = socket_pair();
        client
            .write_all(b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap_or_else(|error| panic!("{error}"));
        let accepted_deadline = Instant::now() + Duration::from_millis(80);
        thread::sleep(Duration::from_millis(120));
        let started = Instant::now();
        assert!(read_request(&mut server, 1024, accepted_deadline).is_err());
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn readiness_rescans_mutation_that_arrives_during_scan() {
        let mut watcher = FakeWatch {
            results: VecDeque::from([Ok(WatchResult::Changed), Ok(WatchResult::Timeout)]),
        };
        let shutdown = AtomicBool::new(false);
        let mut scans = 0;
        assert!(scan_until_quiescent(
            &mut watcher,
            &shutdown,
            || {
                scans += 1;
                true
            },
            || panic!("replacement was not expected"),
        ));
        assert_eq!(scans, 2);
    }

    #[test]
    fn readiness_replaces_watch_after_every_overflow_before_rescanning() {
        let mut watcher = FakeWatch {
            results: VecDeque::from([
                Ok(WatchResult::Overflow),
                Ok(WatchResult::Overflow),
                Ok(WatchResult::Timeout),
            ]),
        };
        let shutdown = AtomicBool::new(false);
        let mut scans = 0;
        let mut replacements = 0;
        assert!(scan_until_quiescent(
            &mut watcher,
            &shutdown,
            || {
                scans += 1;
                true
            },
            || {
                replacements += 1;
                Ok(FakeWatch {
                    results: VecDeque::from(if replacements == 1 {
                        [Ok(WatchResult::Overflow), Ok(WatchResult::Timeout)]
                    } else {
                        [Ok(WatchResult::Timeout), Ok(WatchResult::Timeout)]
                    }),
                })
            },
        ));
        assert_eq!(scans, 3);
        assert_eq!(replacements, 2);
    }

    #[test]
    fn startup_readiness_fails_closed_on_scan_or_replacement_failure() {
        let shutdown = AtomicBool::new(false);
        let mut scan_failure = FakeWatch {
            results: VecDeque::from([Ok(WatchResult::Timeout)]),
        };
        assert!(!scan_until_quiescent(
            &mut scan_failure,
            &shutdown,
            || false,
            || panic!("replacement was not expected"),
        ));

        let mut replacement_failure = FakeWatch {
            results: VecDeque::from([Ok(WatchResult::Overflow)]),
        };
        assert!(!scan_until_quiescent(
            &mut replacement_failure,
            &shutdown,
            || true,
            || Err(Error::new(ErrorClass::State, "replacement failed")),
        ));
    }
}
