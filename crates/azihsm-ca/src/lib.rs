//! Persistent Windows-only AziHSM demonstration certificate authority.

#[cfg(not(windows))]
compile_error!("azihsm-ca is Windows-only");

#[cfg(windows)]
pub mod authority;
#[cfg(windows)]
pub mod cert;
#[cfg(windows)]
pub mod cli;
#[cfg(windows)]
pub mod csr;
#[cfg(windows)]
pub mod error;
#[cfg(windows)]
pub mod http;
#[cfg(windows)]
pub mod operations;
#[cfg(windows)]
pub mod policy;
#[cfg(windows)]
pub mod state;
#[cfg(windows)]
pub mod win;
