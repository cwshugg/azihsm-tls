//! Fixed compact stdout tracing with a closed global level grammar.

use crate::{Error, ErrorClass, Result};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::Subscriber;

pub fn init() -> Result<()> {
    let level = match std::env::var("RUST_LOG").as_deref() {
        Ok("off") => LevelFilter::OFF,
        Ok("error") => LevelFilter::ERROR,
        Ok("warn") => LevelFilter::WARN,
        Ok("info") | Err(std::env::VarError::NotPresent) => LevelFilter::INFO,
        Ok("debug") => LevelFilter::DEBUG,
        Ok("trace") => LevelFilter::TRACE,
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
            return Err(Error::new(
                ErrorClass::Usage,
                "RUST_LOG must be one of off, error, warn, info, debug, or trace",
            ));
        }
    };
    let subscriber = Subscriber::builder()
        .with_max_level(level)
        .with_writer(std::io::stdout)
        .without_time()
        .with_target(false)
        .with_ansi(false)
        .compact()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::fmt::Subscriber;

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
    fn compact_format_contains_no_ansi_or_sensitive_values() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Subscriber::builder()
            .with_max_level(tracing::Level::INFO)
            .with_writer(Capture(Arc::clone(&bytes)))
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                event = "handshake_completed",
                connection_id = 7_u64,
                message = "The client accepted the server certificate and AziHSM signed CertificateVerify; no client identity was authenticated."
            );
            crate::identity::log_renewal_started();
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
        assert!(output.contains("event=\"handshake_completed\""));
        assert!(output.contains("The client accepted the server certificate"));
        assert!(output.contains("no client identity was authenticated"));
        let renewal = output
            .lines()
            .find(|line| line.contains("event=\"certificate_renewal_started\""))
            .unwrap_or_else(|| panic!("renewal start event was not captured"));
        assert!(renewal.trim_start().starts_with("INFO "));
        assert!(!renewal.contains("WARN"));
        assert!(!output.contains(concat!("server authenticated", " the client")));
        assert!(!output.contains("must_be_filtered"));
        assert!(!output.contains('\u{1b}'));
        for sensitive in [
            "secret-key-name",
            "server.private.internal",
            "fedcba9876543210fedcba9876543210",
            "C:\\private\\output",
        ] {
            assert!(!output.contains(sensitive));
        }
    }
}
