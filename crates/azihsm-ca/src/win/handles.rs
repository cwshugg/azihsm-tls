//! Non-clone RAII wrappers for Windows cryptographic resources.

use windows_sys::Win32::Security::Cryptography::{
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCryptFreeObject,
};

#[derive(Debug)]
pub struct NcryptProvider(pub NCRYPT_PROV_HANDLE);

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
}

impl Drop for NcryptKey {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: this wrapper uniquely owns the key handle.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}
