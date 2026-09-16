//! AziHSM-backed TLS certificate enrollment workflow.

#[cfg(not(windows))]
compile_error!("azihsm-ca-demo is Windows-only");

pub mod cli;
mod csr;
mod files;
mod http;
pub mod logging;
mod model;
pub mod transcript;
mod verify;
pub mod workflow;

pub use azihsm_ncrypt::{Error, ErrorClass, Result};
