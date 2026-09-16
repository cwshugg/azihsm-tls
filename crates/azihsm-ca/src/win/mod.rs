//! Safe ownership wrappers and Windows cryptography operations.

pub mod crypt32;
pub mod handles;
pub mod ncrypt;

use crate::error::{Error, ErrorClass};

pub(crate) fn status_error(class: ErrorClass, operation: &str, status: i32) -> Error {
    if operation.starts_with("NCrypt") {
        tracing::error!(
            event = "ncrypt_operation_failed",
            operation,
            status = format_args!("0x{:08x}", status as u32)
        );
    }
    Error::new(
        class,
        format!("{operation} failed with status 0x{:08x}", status as u32),
    )
}

pub(crate) fn bool_error(class: ErrorClass, operation: &str) -> Error {
    // SAFETY: GetLastError has no preconditions and is called immediately after a BOOL failure.
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    Error::new(class, format!("{operation} failed with Win32 error {code}"))
}

pub(crate) fn usize_to_u32(value: usize, operation: &str) -> crate::error::Result<u32> {
    u32::try_from(value).map_err(|_| {
        Error::new(
            ErrorClass::Validation,
            format!("{operation} length overflow"),
        )
    })
}
