// Copyright (C) Microsoft Corporation. All rights reserved.

use crate::error::{Error, ExitCode, Result};
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
                ExitCode::Usage,
                "RUST_LOG must be one of off, error, warn, info, debug, or trace",
            ));
        }
    };
    let subscriber = Subscriber::builder()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .with_ansi(false)
        .compact()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    Ok(())
}
