//! Non-clone RAII wrappers for Windows cryptographic resources.

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_KEY_HANDLE, BCryptCloseAlgorithmProvider,
    BCryptDestroyHash, BCryptDestroyKey, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCryptFreeObject,
};

use crate::error::{ErrorClass, Result};
use crate::win::status_error;

#[derive(Debug)]
pub struct NcryptProvider(pub NCRYPT_PROV_HANDLE);

impl NcryptProvider {
    pub fn release(mut self) -> Result<i32> {
        // SAFETY: this wrapper uniquely owns the provider handle.
        let status = unsafe { NCryptFreeObject(self.0) };
        self.0 = 0;
        checked_provider_release_status(status)
    }
}

fn checked_provider_release_status(status: i32) -> Result<i32> {
    if status < 0 {
        return Err(status_error(
            ErrorClass::Cleanup,
            "NCryptFreeObject(provider)",
            status,
        ));
    }
    Ok(status)
}

impl Drop for NcryptProvider {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: this wrapper uniquely owns the provider handle.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

#[derive(Debug)]
pub struct NcryptKey(pub NCRYPT_KEY_HANDLE);

impl NcryptKey {
    pub fn disarm(&mut self) {
        self.0 = 0;
    }

    pub fn release(mut self) -> Result<()> {
        // SAFETY: this wrapper uniquely owns the key handle.
        let status = unsafe { NCryptFreeObject(self.0) };
        self.0 = 0;
        if status < 0 {
            return Err(status_error(
                ErrorClass::Cleanup,
                "NCryptFreeObject(key)",
                status,
            ));
        }
        Ok(())
    }
}

impl Drop for NcryptKey {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: this wrapper uniquely owns the key handle.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

#[derive(Debug)]
pub struct BcryptAlgorithm(pub BCRYPT_ALG_HANDLE);

impl BcryptAlgorithm {
    pub fn release(mut self) -> Result<()> {
        // SAFETY: this wrapper uniquely owns the algorithm handle.
        let status = unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
        self.0 = std::ptr::null_mut();
        if status < 0 {
            return Err(status_error(
                ErrorClass::Cleanup,
                "BCryptCloseAlgorithmProvider",
                status,
            ));
        }
        Ok(())
    }
}

impl Drop for BcryptAlgorithm {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the algorithm handle.
            unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
        }
    }
}

#[derive(Debug)]
pub struct BcryptKey(pub BCRYPT_KEY_HANDLE);

impl BcryptKey {
    pub fn release(mut self) -> Result<()> {
        // SAFETY: this wrapper uniquely owns the key handle.
        let status = unsafe { BCryptDestroyKey(self.0) };
        self.0 = std::ptr::null_mut();
        if status < 0 {
            return Err(status_error(
                ErrorClass::Cleanup,
                "BCryptDestroyKey",
                status,
            ));
        }
        Ok(())
    }
}

impl Drop for BcryptKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the key handle.
            unsafe { BCryptDestroyKey(self.0) };
        }
    }
}

#[derive(Debug)]
pub struct BcryptHash(pub BCRYPT_HASH_HANDLE);

impl BcryptHash {
    pub fn release(mut self) -> Result<()> {
        // SAFETY: this wrapper uniquely owns the hash handle.
        let status = unsafe { BCryptDestroyHash(self.0) };
        self.0 = std::ptr::null_mut();
        if status < 0 {
            return Err(status_error(
                ErrorClass::Cleanup,
                "BCryptDestroyHash",
                status,
            ));
        }
        Ok(())
    }
}

impl Drop for BcryptHash {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the hash handle.
            unsafe { BCryptDestroyHash(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::checked_provider_release_status;

    #[test]
    fn provider_release_failure_is_not_accepted_as_cleanup() {
        assert!(checked_provider_release_status(-1).is_err());
        assert_eq!(
            checked_provider_release_status(0).unwrap_or_else(|error| panic!("{error}")),
            0
        );
    }
}
