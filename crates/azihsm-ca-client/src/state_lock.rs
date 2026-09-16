//! Exclusive Windows locking for shared enrollment and TLS state.

use crate::{Error, ErrorClass, Result};
use std::fs::{File, OpenOptions};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

pub const STATE_LOCK_FILE: &str = ".azihsm-state.lock";

/// Holds the exclusive state mutation lock until dropped.
pub struct StateLock {
    file: File,
    path: PathBuf,
}

impl std::fmt::Debug for StateLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateLock")
            .field("held", &true)
            .finish_non_exhaustive()
    }
}

impl StateLock {
    /// Creates or validates the state directory and acquires its exclusive lock.
    pub fn acquire(state_dir: &Path) -> Result<Self> {
        if state_dir.exists() {
            crate::files::validate_output_dir(state_dir)?;
        } else {
            crate::files::create_output_dir(state_dir)?;
        }
        let path = state_dir.join(STATE_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| state(format!("cannot open state lock: {error}")))?;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: the file and OVERLAPPED remain live for this synchronous lock call.
        let locked = unsafe {
            LockFileEx(
                file.as_raw_handle().cast(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if locked == 0 {
            return Err(state("state is locked by another process"));
        }
        tracing::info!(
            event = "state_lock_acquired",
            message = "Holding the exclusive state lock so another demo or server process cannot mutate this identity."
        );
        Ok(Self { file, path })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: this object owns the still-live file used to acquire this range.
        let unlocked = unsafe {
            UnlockFileEx(
                self.file.as_raw_handle().cast(),
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if unlocked == 0 {
            tracing::error!(
                event = "state_lock_release_failed",
                message = "The operating system did not confirm release of the state lock."
            );
        } else {
            tracing::info!(
                event = "state_lock_released",
                message = "Released the exclusive state lock after key and state use completed."
            );
        }
        let _ = &self.path;
    }
}

fn state(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::StateBusy, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_lock_rejects_contention_and_recovers() {
        let path = std::env::current_dir()
            .unwrap_or_else(|error| panic!("{error}"))
            .join("target")
            .join(format!("state-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let first = StateLock::acquire(&path).unwrap_or_else(|error| panic!("{error}"));
        assert!(StateLock::acquire(&path).is_err());
        drop(first);
        StateLock::acquire(&path).unwrap_or_else(|error| panic!("{error}"));
        std::fs::remove_dir_all(path).unwrap_or_else(|error| panic!("{error}"));
    }
}
