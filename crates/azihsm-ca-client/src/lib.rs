//! Neutral client primitives for the AziHSM demonstration CA protocol.

pub mod artifacts;
pub mod csr;
pub mod files;
mod http;
mod logging;
pub mod model;
pub mod state_lock;
pub mod transcript;
pub mod validation;
pub mod verify;

pub use azihsm_ncrypt::{Error, ErrorClass, Result};
pub use http::{CaClient, CaFailure, CaFailureKind, CaOperation, Enrollment};
pub use logging::{
    error as error_event, info as info_event, init as init_logging, warn as warn_event,
};
pub use model::{CaError, CaErrorDetail, CaMetadata, ReadyResponse};
