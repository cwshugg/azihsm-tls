//! Registered-provider NCrypt operations for user-scoped named P-256 keys.

use crate::error::{Error, ErrorClass, Result};
use crate::policy::{MAX_ECC_BLOB, MAX_SIGNATURE};
use crate::win::bcrypt::{hash_sha256, import_public, validate_public_blob};
use crate::win::handles::{NcryptKey, NcryptProvider};
use crate::win::status_error;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
use windows_sys::Win32::Security::Cryptography::*;

pub const E_UNEXPECTED_STATUS: i32 = 0x8000_ffff_u32 as i32;

#[derive(Debug)]
pub struct AziProvider {
    pub handle: NcryptProvider,
}

impl AziProvider {
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

    pub fn open_key(&self, key_name: &str) -> std::result::Result<AziKey, i32> {
        let name = wide_status(key_name)?;
        let mut key = 0;
        // SAFETY: provider, output, and terminated key name are valid. Flags fix user scope.
        let status = unsafe { NCryptOpenKey(self.handle.0, &mut key, name.as_ptr(), 0, 0) };
        if status < 0 {
            return Err(status);
        }
        Ok(AziKey {
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

    pub fn create_named_staged(&self, key_name: &str) -> Result<AziKey> {
        let name = wide(key_name)?;
        let mut key = 0;
        // SAFETY: provider, output, algorithm, and key name are valid. Key spec and flags
        // are deliberately zero: current-user scope, no machine flag, and no overwrite.
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
        Ok(AziKey {
            key: NcryptKey(key),
        })
    }
}

#[derive(Debug)]
pub struct AziKey {
    pub key: NcryptKey,
}

impl AziKey {
    pub fn finalize(&self) -> i32 {
        // SAFETY: key is a live staged key. Flags are deliberately zero.
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
        validate_public_blob(&blob)?;
        Ok(blob)
    }

    pub fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
        let mut size = 0;
        // SAFETY: null output is the documented sizing call.
        let status = unsafe {
            NCryptSignHash(
                self.key.0,
                null(),
                digest.as_ptr(),
                digest.len() as u32,
                null_mut(),
                0,
                &mut size,
                0,
            )
        };
        if status < 0 || size != 64 || size as usize > MAX_SIGNATURE {
            return Err(status_error(
                ErrorClass::Issuance,
                "NCryptSignHash(size)",
                status,
            ));
        }
        let mut signature = [0; 64];
        // SAFETY: all pointer/length pairs are valid.
        let status = unsafe {
            NCryptSignHash(
                self.key.0,
                null(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut size,
                0,
            )
        };
        if status < 0 || size != signature.len() as u32 {
            return Err(status_error(ErrorClass::Issuance, "NCryptSignHash", status));
        }
        Ok(signature)
    }

    pub fn kat(&self) -> Result<()> {
        let challenge = crate::win::bcrypt::random::<32>()?;
        let digest = hash_sha256(&challenge)?;
        let signature = self.sign(&digest)?;
        let verifier = import_public(&self.public_blob()?)?;
        verifier.verify(&digest, &signature)?;
        Ok(())
    }
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
