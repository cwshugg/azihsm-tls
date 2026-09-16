//! Shared compact tracing initialization and static human narration.

use crate::{Error, ErrorClass, Result};
use std::ffi::OsStr;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::Subscriber;

pub fn init() -> Result<()> {
    let subscriber = Subscriber::builder()
        .with_max_level(parse_level(std::env::var_os("RUST_LOG").as_deref())?)
        .with_writer(std::io::stdout)
        .without_time()
        .with_target(false)
        .with_ansi(false)
        .compact()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    Ok(())
}

fn parse_level(value: Option<&OsStr>) -> Result<LevelFilter> {
    match value.and_then(OsStr::to_str) {
        None if value.is_none() => Ok(LevelFilter::INFO),
        Some("off") => Ok(LevelFilter::OFF),
        Some("error") => Ok(LevelFilter::ERROR),
        Some("warn") => Ok(LevelFilter::WARN),
        Some("info") => Ok(LevelFilter::INFO),
        Some("debug") => Ok(LevelFilter::DEBUG),
        Some("trace") => Ok(LevelFilter::TRACE),
        _ => Err(Error::new(
            ErrorClass::Usage,
            "RUST_LOG must be one of off, error, warn, info, debug, or trace",
        )),
    }
}

// The applications expose only a closed global level, so sharing these callsites cannot
// collapse module-specific filtering that users could otherwise select.
pub fn info(event: &'static str, message: &'static str) {
    tracing::info!(event, message);
}

pub fn warn(event: &'static str, message: &'static str) {
    tracing::warn!(event, message);
}

pub fn error(event: &'static str, message: &'static str) {
    tracing::error!(event, message);
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
    fn exact_levels_and_compact_static_events_are_shared() {
        for (text, expected) in [
            ("off", LevelFilter::OFF),
            ("error", LevelFilter::ERROR),
            ("warn", LevelFilter::WARN),
            ("info", LevelFilter::INFO),
            ("debug", LevelFilter::DEBUG),
            ("trace", LevelFilter::TRACE),
        ] {
            assert_eq!(parse_level(Some(OsStr::new(text))).unwrap(), expected);
        }
        assert_eq!(parse_level(None).unwrap(), LevelFilter::INFO);
        assert!(parse_level(Some(OsStr::new("info,crate=debug"))).is_err());

        let bytes = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Subscriber::builder()
            .with_max_level(LevelFilter::INFO)
            .with_writer(Capture(Arc::clone(&bytes)))
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            info("shared_info", "A concise human description.");
            warn("shared_warn", "A bounded warning.");
            tracing::debug!(event = "must_be_filtered");
        });
        let output = String::from_utf8(
            bytes
                .lock()
                .unwrap_or_else(|error| panic!("{error}"))
                .clone(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(output.contains("INFO"));
        assert!(output.contains("event=\"shared_info\""));
        assert!(output.contains("A concise human description."));
        assert!(output.contains("WARN"));
        assert!(output.contains("event=\"shared_warn\""));
        assert!(!output.contains("must_be_filtered"));
        assert!(!output.contains('\u{1b}'));
    }
}
