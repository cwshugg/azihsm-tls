//! Registered-provider NCrypt operations for user-scoped named P-256 keys.

use crate::handles::{NcryptKey, NcryptProvider};
use crate::{Error, ErrorClass, Result, hash_sha256, public_point, random, verify_p256_sha256};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
use windows_sys::Win32::Security::Cryptography::*;

#[cfg(test)]
static SIGN_HASH_CALLS: AtomicUsize = AtomicUsize::new(0);
static LOGICAL_SIGNATURES: AtomicUsize = AtomicUsize::new(0);

pub const PROVIDER_NAME: &str = "Microsoft Azure Integrated HSM Key Storage Provider";
pub const E_UNEXPECTED_STATUS: i32 = 0x8000_ffff_u32 as i32;
const MAX_ECC_BLOB: usize = 1024;
const MAX_SIGNATURE: usize = 256;

#[derive(Debug)]
pub struct AzihsmProvider {
    handle: NcryptProvider,
}

impl AzihsmProvider {
    pub fn open_named(provider_name: &str) -> Result<Self> {
        let name = wide(provider_name)?;
        let mut handle = 0;
        // SAFETY: the output pointer and terminated provider name are valid.
        let status = unsafe { NCryptOpenStorageProvider(&mut handle, name.as_ptr(), 0) };
        if status < 0 {
            return Err(status_error(
                ErrorClass::Provider,
                "NCryptOpenStorageProvider",
                status,
            ));
        }
        let provider = NcryptProvider(handle);
        // SAFETY: provider is live and the algorithm identifier is a system constant.
        let status = unsafe { NCryptIsAlgSupported(provider.0, BCRYPT_ECDSA_P256_ALGORITHM, 0) };
        if status < 0 {
            return Err(status_error(
                ErrorClass::Provider,
                "NCryptIsAlgSupported(ECDSA_P256)",
                status,
            ));
        }
        Ok(Self { handle: provider })
    }

    pub fn open_key(&self, key_name: &str) -> std::result::Result<AzihsmKey, i32> {
        let name = wide_status(key_name)?;
        let mut key = 0;
        // SAFETY: provider, output, and terminated key name are valid. Zero flags select user scope.
        let status = unsafe { NCryptOpenKey(self.handle.0, &mut key, name.as_ptr(), 0, 0) };
        if status < 0 {
            return Err(status);
        }
        Ok(AzihsmKey {
            key: NcryptKey(key),
        })
    }

    pub fn require_absent(&self, key_name: &str) -> Result<()> {
        match self.open_key(key_name) {
            Err(status) if status == NTE_BAD_KEYSET => Ok(()),
            Err(status) => Err(status_error(
                ErrorClass::Provider,
                "NCryptOpenKey(absence preflight)",
                status,
            )),
            Ok(_) => Err(Error::new(
                ErrorClass::AlreadyInitialized,
                "the requested named key already exists",
            )),
        }
    }

    pub fn create_named_staged(&self, key_name: &str) -> Result<AzihsmKey> {
        let name = wide(key_name)?;
        let mut key = 0;
        // SAFETY: all pointers are valid. Zero flags mean user scope and prohibit overwrite.
        let status = unsafe {
            NCryptCreatePersistedKey(
                self.handle.0,
                &mut key,
                BCRYPT_ECDSA_P256_ALGORITHM,
                name.as_ptr(),
                0,
                0,
            )
        };
        if status < 0 {
            return Err(status_error(
                ErrorClass::Provider,
                "NCryptCreatePersistedKey",
                status,
            ));
        }
        Ok(AzihsmKey {
            key: NcryptKey(key),
        })
    }
}

#[derive(Debug)]
pub struct AzihsmKey {
    key: NcryptKey,
}

/// Owns one provider and one named key for the full signing lifetime.
///
/// Field order is intentional: Rust drops `key` before `provider`.
#[derive(Debug)]
pub struct AzihsmSession {
    key: Mutex<AzihsmKey>,
    provider: AzihsmProvider,
}

impl AzihsmSession {
    /// Opens an existing current-user named key and keeps its provider alive.
    pub fn open(provider_name: &str, key_name: &str) -> Result<Self> {
        let provider = AzihsmProvider::open_named(provider_name)?;
        let key = provider.open_key(key_name).map_err(|status| {
            status_error(ErrorClass::Provider, "NCryptOpenKey(session)", status)
        })?;
        Ok(Self {
            key: Mutex::new(key),
            provider,
        })
    }

    /// Runs the provider-backed key self-test.
    pub fn kat(&self) -> Result<()> {
        self.lock()?.kat()
    }

    /// Exports only the public P-256 blob.
    pub fn public_blob(&self) -> Result<[u8; 72]> {
        self.lock()?.public_blob()
    }

    /// Signs one SHA-256 digest and records one logical production signature.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
        tracing::debug!(event = "certificate_verify_sign_started");
        let signature = self.lock()?.sign(digest)?;
        LOGICAL_SIGNATURES.fetch_add(1, Ordering::SeqCst);
        tracing::info!(event = "certificate_verify_sign_completed");
        Ok(signature)
    }

    /// Deletes the uniquely owned named key while its provider remains live.
    pub fn delete(self) -> Result<()> {
        let key = self.key.into_inner().map_err(|_| {
            Error::new(ErrorClass::Provider, "AziHSM key session mutex is poisoned")
        })?;
        key.delete()?;
        drop(self.provider);
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, AzihsmKey>> {
        self.key
            .lock()
            .map_err(|_| Error::new(ErrorClass::Provider, "AziHSM key session mutex is poisoned"))
    }
}

/// Returns the process-wide count of completed logical session signatures.
pub fn logical_signature_count() -> usize {
    LOGICAL_SIGNATURES.load(Ordering::SeqCst)
}

impl AzihsmKey {
    pub fn finalize(&self) -> i32 {
        // SAFETY: key is a live staged key. Zero flags prohibit overwrite.
        unsafe { NCryptFinalizeKey(self.key.0, 0) }
    }

    pub fn public_blob(&self) -> Result<[u8; 72]> {
        let mut size = 0;
        // SAFETY: null output is the documented sizing call.
        let status = unsafe {
            NCryptExportKey(
                self.key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null(),
                null_mut(),
                0,
                &mut size,
                0,
            )
        };
        if status < 0 || size != 72 || size as usize > MAX_ECC_BLOB {
            return Err(status_error(
                ErrorClass::Validation,
                "NCryptExportKey(size)",
                status,
            ));
        }
        let mut blob = [0_u8; 72];
        // SAFETY: output has exactly the queried writable capacity.
        let status = unsafe {
            NCryptExportKey(
                self.key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null(),
                blob.as_mut_ptr(),
                blob.len() as u32,
                &mut size,
                0,
            )
        };
        if status < 0 || size != blob.len() as u32 {
            return Err(status_error(
                ErrorClass::Validation,
                "NCryptExportKey",
                status,
            ));
        }
        public_point(&blob)?;
        Ok(blob)
    }

    pub fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
        let mut size = 0;
        let status = ncrypt_sign_hash(self.key.0, digest, None, &mut size);
        if status < 0 || size != 64 || size as usize > MAX_SIGNATURE {
            return Err(status_error(
                ErrorClass::Issuance,
                "NCryptSignHash sizing",
                status,
            ));
        }
        let mut signature = [0; 64];
        let status = ncrypt_sign_hash(self.key.0, digest, Some(&mut signature), &mut size);
        if status < 0 || size != signature.len() as u32 {
            return Err(status_error(ErrorClass::Issuance, "NCryptSignHash", status));
        }
        Ok(signature)
    }

    pub fn kat(&self) -> Result<()> {
        let challenge = random::<32>()?;
        let digest = hash_sha256(&challenge)?;
        let signature = self.sign(&digest)?;
        verify_p256_sha256(&self.public_blob()?, &challenge, &signature)
    }

    pub fn delete(mut self) -> Result<()> {
        // SAFETY: this object uniquely owns the exact key handle being deleted.
        let status = unsafe { NCryptDeleteKey(self.key.0, 0) };
        if status < 0 {
            return Err(status_error(
                ErrorClass::Provider,
                "NCryptDeleteKey",
                status,
            ));
        }
        self.key.disarm();
        Ok(())
    }
}

fn ncrypt_sign_hash(
    key: NCRYPT_KEY_HANDLE,
    digest: &[u8; 32],
    output: Option<&mut [u8; 64]>,
    size: &mut u32,
) -> i32 {
    #[cfg(test)]
    SIGN_HASH_CALLS.fetch_add(1, Ordering::SeqCst);
    let (pointer, capacity) = output
        .map(|bytes| (bytes.as_mut_ptr(), bytes.len() as u32))
        .unwrap_or((null_mut(), 0));
    // SAFETY: the key and digest are valid, and output is either null or has the given capacity.
    unsafe {
        NCryptSignHash(
            key,
            null(),
            digest.as_ptr(),
            digest.len() as u32,
            pointer,
            capacity,
            size,
            0,
        )
    }
}

fn status_error(class: ErrorClass, operation: &str, status: i32) -> Error {
    tracing::error!(
        event = "ncrypt_operation_failed",
        operation,
        status = format_args!("0x{:08x}", status as u32)
    );
    Error::new(
        class,
        format!("{operation} failed with status 0x{:08x}", status as u32),
    )
}

fn wide(value: &str) -> Result<Vec<u16>> {
    wide_status(value).map_err(|_| Error::new(ErrorClass::Usage, "text contains a NUL code unit"))
}

fn wide_status(value: &str) -> std::result::Result<Vec<u16>, i32> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(windows_sys::Win32::Foundation::E_INVALIDARG);
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::SigningKey;
    use std::sync::{Arc, Mutex};

    #[test]
    fn owned_session_field_order_drops_key_before_provider() {
        #[derive(Debug)]
        struct Marker(&'static str, Arc<Mutex<Vec<&'static str>>>);
        impl Drop for Marker {
            fn drop(&mut self) {
                self.1
                    .lock()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .push(self.0);
            }
        }
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Session {
            key: Marker,
            provider: Marker,
        }
        let order = Arc::new(Mutex::new(Vec::new()));
        drop(Session {
            key: Marker("key", Arc::clone(&order)),
            provider: Marker("provider", Arc::clone(&order)),
        });
        assert_eq!(
            *order.lock().unwrap_or_else(|error| panic!("{error}")),
            ["key", "provider"]
        );
    }

    #[test]
    #[ignore = "requires registered named AziHSM test provider"]
    fn rcgen_adapter_makes_exactly_two_native_calls() {
        let provider =
            AzihsmProvider::open_named(PROVIDER_NAME).unwrap_or_else(|error| panic!("{error}"));
        let key_name = format!(
            "azihsm-ncrypt-adapter-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|error| panic!("{error}"))
                .as_nanos()
        );
        provider
            .require_absent(&key_name)
            .unwrap_or_else(|error| panic!("{error}"));
        let key = provider
            .create_named_staged(&key_name)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(key.finalize(), 0);
        let blob = key.public_blob().unwrap_or_else(|error| panic!("{error}"));
        let adapter =
            crate::AzihsmSigningKey::new(&key, &blob).unwrap_or_else(|error| panic!("{error}"));
        let before = SIGN_HASH_CALLS.load(Ordering::SeqCst);
        adapter
            .sign(b"production adapter call-count proof")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(SIGN_HASH_CALLS.load(Ordering::SeqCst) - before, 2);
        drop(adapter);
        key.delete().unwrap_or_else(|error| panic!("{error}"));
    }
}
