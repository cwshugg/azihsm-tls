//! Safe, narrow wrappers for named user-scoped AziHSM P-256 keys.

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(not(windows))]
compile_error!("azihsm-ncrypt is Windows-only");

mod crypto;
mod error;
mod handles;
mod ncrypt;
mod signer;

pub use crypto::{hash_sha1, hash_sha256, public_point, random, verify_p256_sha256};
pub use error::{Error, ErrorClass, Result};
pub use ncrypt::{AzihsmKey, AzihsmProvider, E_UNEXPECTED_STATUS, PROVIDER_NAME};
pub use signer::{AzihsmSigningKey, PublicP256Key, p1363_to_der};
