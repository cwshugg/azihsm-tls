//! Compile-time smoke coverage for every Windows API family used by the product.

#![cfg(windows)]

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::Cryptography::{
    CertCreateCertificateContext, CryptVerifyCertificateSignatureEx, NCryptCreatePersistedKey,
    NCryptFinalizeKey, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash,
};
use windows_sys::Win32::Security::{GetFileSecurityW, GetTokenInformation};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FlushFileBuffers, LockFileEx, ReadDirectoryChangesW,
    UnlockFileEx,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult};
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenProcessToken, ResetEvent, WaitForSingleObject,
};

#[test]
fn used_windows_bindings_are_available() {
    let _: unsafe extern "system" fn(HANDLE) -> i32 = CloseHandle;
    let _ = FlushFileBuffers;
    let _ = CertCreateCertificateContext;
    let _ = CryptVerifyCertificateSignatureEx;
    let _ = NCryptCreatePersistedKey;
    let _ = NCryptFinalizeKey;
    let _ = NCryptOpenKey;
    let _ = NCryptOpenStorageProvider;
    let _ = NCryptSignHash;
    let _ = LockFileEx;
    let _ = UnlockFileEx;
    let _ = ReadDirectoryChangesW;
    let _ = CreateDirectoryW;
    let _ = CreateFileW;
    let _ = GetFileSecurityW;
    let _ = GetTokenInformation;
    let _ = ConvertSecurityDescriptorToStringSecurityDescriptorW;
    let _ = ConvertSidToStringSidW;
    let _ = ConvertStringSecurityDescriptorToSecurityDescriptorW;
    let _ = CancelIoEx;
    let _ = GetOverlappedResult;
    let _ = CreateEventW;
    let _ = OpenProcessToken;
    let _ = ResetEvent;
    let _ = WaitForSingleObject;
}
