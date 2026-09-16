//! Expiry-aware Tokio listener, admission, TLS, framing, and draining.

use crate::frame::{PREFIX, ReadFrame, read_frame, transcript, write_response};
use rustls::ServerConfig;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsAcceptor;

const MAX_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Admission {
    permits: Arc<Semaphore>,
}

impl Admission {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    #[doc(hidden)]
    pub fn acquire(&self) -> io::Result<OwnedSemaphorePermit> {
        Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "connection limit reached"))
    }
}

/// Supplies production connection timing and a pre-response scheduling point.
#[doc(hidden)]
pub trait ConnectionRuntime: Send + Sync {
    fn now(&self) -> Instant;

    fn handshake_timeout(&self) -> Duration {
        HANDSHAKE_TIMEOUT
    }

    fn read_timeout(&self) -> Duration {
        READ_TIMEOUT
    }

    fn write_timeout(&self) -> Duration {
        WRITE_TIMEOUT
    }

    fn before_response(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::ready(()))
    }
}

#[derive(Debug)]
struct TokioConnectionRuntime;

impl ConnectionRuntime for TokioConnectionRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub async fn run(
    listen: SocketAddr,
    config: Arc<ServerConfig>,
    not_after: OffsetDateTime,
) -> io::Result<()> {
    let remaining = not_after.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp();
    if remaining <= 0 {
        return Err(io::Error::other("certificate is expired"));
    }
    let expiry = Instant::now() + Duration::from_secs(remaining as u64);
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(event = "listener_started");
    let admission = Admission::new();
    let connection_runtime: Arc<dyn ConnectionRuntime> = Arc::new(TokioConnectionRuntime);
    let next_id = AtomicU64::new(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(None::<Instant>);
    let mut tasks = JoinSet::new();
    let expired;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let permit = match admission.acquire() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(event = "connection_rejected");
                        drop(stream);
                        continue;
                    }
                };
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                tracing::info!(event = "connection_admitted", connection_id = id);
                let acceptor = TlsAcceptor::from(Arc::clone(&config));
                let receiver = shutdown_rx.clone();
                let runtime = Arc::clone(&connection_runtime);
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) =
                        serve_connection(id, stream, acceptor, expiry, receiver, runtime).await
                    {
                        tracing::warn!(
                            event = "connection_failed",
                            connection_id = id,
                            reason = %error
                        );
                    }
                });
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                expired = false;
                tracing::info!(event = "shutdown_requested");
                break;
            }
            () = tokio::time::sleep_until(expiry) => {
                expired = true;
                tracing::warn!(event = "certificate_expired");
                break;
            }
        }
    }
    drop(listener);
    let drain = if expired {
        Instant::now()
    } else {
        std::cmp::min(Instant::now() + DRAIN_TIMEOUT, expiry)
    };
    let _ = shutdown_tx.send(Some(drain));
    while !tasks.is_empty() && Instant::now() < drain {
        if timeout_at(drain, tasks.join_next()).await.is_err() {
            break;
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    tracing::info!(event = "listener_stopped");
    Ok(())
}

/// Serves one admitted socket through the production TLS and frame loop.
#[doc(hidden)]
pub async fn serve_connection(
    id: u64,
    stream: TcpStream,
    acceptor: TlsAcceptor,
    expiry: Instant,
    mut shutdown: watch::Receiver<Option<Instant>>,
    runtime: Arc<dyn ConnectionRuntime>,
) -> io::Result<()> {
    if runtime.now() >= expiry {
        return Err(io::Error::other("certificate expired before handshake"));
    }
    tracing::info!(event = "handshake_started", connection_id = id);
    let deadline = std::cmp::min(runtime.now() + runtime.handshake_timeout(), expiry);
    let mut tls = timeout_at(deadline, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
        .map_err(io::Error::other)?;
    if runtime.now() >= expiry {
        return Err(io::Error::other("certificate expired during handshake"));
    }
    tracing::info!(event = "handshake_completed", connection_id = id);
    let mut sequence = 0_u64;
    loop {
        let deadline = operation_deadline(
            runtime.now(),
            expiry,
            *shutdown.borrow(),
            runtime.read_timeout(),
        );
        let frame = tokio::select! {
            result = timeout_at(deadline, read_frame(&mut tls)) => {
                result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame read timed out"))??
            }
            changed = shutdown.changed() => {
                let _ = changed;
                close_notify(id, &mut tls, expiry, runtime.as_ref()).await;
                return Ok(());
            }
        };
        let request = match frame {
            ReadFrame::Eof => {
                close_notify(id, &mut tls, expiry, runtime.as_ref()).await;
                return Ok(());
            }
            ReadFrame::Payload(payload) => payload,
        };
        sequence += 1;
        transcript(id, sequence, "received", &request);
        runtime.before_response().await;
        if runtime.now() >= expiry {
            return Err(io::Error::other("certificate expired before response"));
        }
        let deadline = operation_deadline(
            runtime.now(),
            expiry,
            *shutdown.borrow(),
            runtime.write_timeout(),
        );
        timeout_at(deadline, write_response(&mut tls, &request))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame write timed out"))??;
        let mut response = Vec::with_capacity(PREFIX.len() + request.len());
        response.extend_from_slice(PREFIX);
        response.extend_from_slice(&request);
        transcript(id, sequence, "sent", &response);
        tracing::info!(
            event = "frame_completed",
            connection_id = id,
            frame_sequence = sequence,
            request_bytes = request.len(),
            response_bytes = response.len()
        );
    }
}

fn operation_deadline(
    now: Instant,
    expiry: Instant,
    shutdown: Option<Instant>,
    duration: Duration,
) -> Instant {
    std::cmp::min(
        std::cmp::min(now + duration, expiry),
        shutdown.unwrap_or(expiry),
    )
}

async fn close_notify(
    id: u64,
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    expiry: Instant,
    runtime: &dyn ConnectionRuntime,
) {
    if runtime.now() >= expiry {
        return;
    }
    let duration = std::cmp::min(
        runtime.write_timeout(),
        expiry.saturating_duration_since(runtime.now()),
    );
    match timeout(duration, stream.shutdown()).await {
        Ok(Ok(())) => tracing::info!(event = "close_notify_completed", connection_id = id),
        _ => tracing::warn!(event = "close_notify_failed", connection_id = id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadlines_clamp_to_shutdown_and_expiry() {
        let now = Instant::now();
        let expiry = now + Duration::from_secs(5);
        let shutdown = now + Duration::from_secs(2);
        assert!(operation_deadline(now, expiry, Some(shutdown), READ_TIMEOUT) <= shutdown);
        assert!(operation_deadline(now, expiry, None, READ_TIMEOUT) <= expiry);
    }

    #[tokio::test]
    async fn production_admission_recovers_from_every_task_exit() {
        let admission = Admission::new();
        let permits = (0..MAX_CONNECTIONS)
            .map(|_| admission.acquire())
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("{error}"));
        let error = admission.acquire().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        drop(permits);
        let normal = admission
            .acquire()
            .unwrap_or_else(|error| panic!("{error}"));
        drop(normal);

        let handshake_failure = admission
            .acquire()
            .unwrap_or_else(|error| panic!("{error}"));
        tokio::spawn(async move {
            let _permit = handshake_failure;
            Err::<(), _>(io::Error::other("injected handshake failure"))
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_err();
        assert!(admission.acquire().is_ok());

        let panic_permit = admission
            .acquire()
            .unwrap_or_else(|error| panic!("{error}"));
        let panicked = tokio::spawn(async move {
            let _permit = panic_permit;
            panic!("injected task panic");
        })
        .await;
        assert!(panicked.is_err());
        assert!(admission.acquire().is_ok());

        let cancelled = admission
            .acquire()
            .unwrap_or_else(|error| panic!("{error}"));
        let task = tokio::spawn(async move {
            let _permit = cancelled;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.is_err());
        assert!(admission.acquire().is_ok());
    }
}
