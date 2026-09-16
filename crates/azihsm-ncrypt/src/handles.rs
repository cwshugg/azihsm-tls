//! Non-clone RAII wrappers for NCrypt resources.

use windows_sys::Win32::Security::Cryptography::{
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCryptFreeObject,
};

#[derive(Debug)]
pub(crate) struct NcryptProvider(pub(crate) NCRYPT_PROV_HANDLE);

impl Drop for NcryptProvider {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: this wrapper uniquely owns the provider handle.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

#[derive(Debug)]
pub(crate) struct NcryptKey(pub(crate) NCRYPT_KEY_HANDLE);

impl NcryptKey {
    pub(crate) fn disarm(&mut self) {
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
