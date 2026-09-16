//! Minimal validated stdout logging for server and opt-in offline diagnostics.

use crate::error::{Error, ErrorClass, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::Subscriber;

static REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn init(serve: bool) -> Result<()> {
    let configured = std::env::var("RUST_LOG").ok();
    if !serve && configured.is_none() {
        return Ok(());
    }
    let level = configured
        .as_deref()
        .map(parse_level)
        .transpose()?
        .unwrap_or(LevelFilter::INFO);
    REQUESTED.store(true, Ordering::Release);
    install_stdout(level);
    Ok(())
}

pub fn enabled() -> bool {
    REQUESTED.load(Ordering::Acquire)
}

fn install_stdout(level: LevelFilter) {
    let subscriber = Subscriber::builder()
        .with_max_level(level)
        .with_writer(std::io::stdout)
        .without_time()
        .with_target(false)
        .with_ansi(false)
        .compact()
        .finish();
    accept_install_result(tracing::subscriber::set_global_default(subscriber));
}

fn accept_install_result<E>(result: std::result::Result<(), E>) {
    let _ = result;
}

fn parse_level(value: &str) -> Result<LevelFilter> {
    match value {
        "off" => Ok(LevelFilter::OFF),
        "error" => Ok(LevelFilter::ERROR),
        "warn" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        "debug" => Ok(LevelFilter::DEBUG),
        "trace" => Ok(LevelFilter::TRACE),
        _ => Err(Error::new(
            ErrorClass::Usage,
            "RUST_LOG must be one of off, error, warn, info, debug, or trace",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
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

    #[test]
    fn accepts_only_one_global_level() {
        for level in ["off", "error", "warn", "info", "debug", "trace"] {
            assert!(parse_level(level).is_ok());
        }
        for invalid in ["INFO", "info,http=debug", "", "verbose"] {
            assert!(parse_level(invalid).is_err());
        }
    }

    #[test]
    fn initialization_is_idempotent_with_an_existing_global_subscriber() {
        let _ =
            tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::default());
        install_stdout(LevelFilter::INFO);
        install_stdout(LevelFilter::DEBUG);
    }

    #[test]
    fn first_install_and_install_conflicts_are_both_nonfatal() {
        accept_install_result::<()>(Ok(()));
        accept_install_result(Err("already installed"));
    }

    #[test]
    fn compact_stdout_format_omits_sensitive_seed_values() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Subscriber::builder()
            .with_max_level(LevelFilter::DEBUG)
            .with_writer(Capture(Arc::clone(&bytes)))
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .compact()
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                event = "server_starting",
                max_connections = 16,
                allow_dns_count = 1,
                allow_ip_count = 0
            );
            tracing::warn!(event = "request_rejected", reason = "rate_limited");
            tracing::error!(
                event = "ncrypt_operation_failed",
                operation = "NCryptSignHash",
                status = "0x80090020"
            );
        });
        let output = String::from_utf8(
            bytes
                .lock()
                .unwrap_or_else(|error| panic!("{error}"))
                .clone(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(output.contains("INFO"));
        assert!(output.contains("event=\"server_starting\""));
        assert!(output.contains("WARN"));
        assert!(output.contains("reason=\"rate_limited\""));
        assert!(output.contains("ERROR"));
        assert!(output.contains("event=\"ncrypt_operation_failed\""));
        assert!(!output.contains('\u{1b}'));
        for forbidden in [
            r"C:\secret-state",
            "seed.example.internal",
            "0123456789abcdef0123456789abcdef",
            "PRIVATE KEY",
        ] {
            assert!(!output.contains(forbidden));
        }
    }
}
