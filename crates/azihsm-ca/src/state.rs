//! Persistent schemas, path validation, exclusive locking, and durable publication.

use crate::crypto::hash_sha256;
use crate::encoding::canonical_json;
use crate::error::{Error, ErrorClass, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_LOCK_VIOLATION, ERROR_NOTIFY_ENUM_DIR,
    ERROR_OPERATION_ABORTED, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetFileSecurityW, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
#[cfg(test)]
use windows_sys::Win32::Security::{PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED,
    FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME, FILE_ACTION_RENAMED_OLD_NAME,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FlushFileBuffers,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, OPEN_ALWAYS,
    ReadDirectoryChangesW, UnlockFileEx,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, ResetEvent, WaitForMultipleObjects,
    WaitForSingleObject,
};

pub const SCHEMA_VERSION: u32 = 1;
pub const STATE_FORMAT_VERSION: u32 = 1;
pub const STATE_PRODUCER: &str = "azihsm-ca-rcgen-actix-v1";
pub const DIRECTORY_NAMES: [&str; 6] = [
    "init-intents",
    "issuances",
    "abandoned-issuances",
    "serial-reservations",
    "idempotency",
    "audit",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateFormat {
    pub format_version: u32,
    pub producer: String,
}

pub fn publish_state_format(state_dir: &Path) -> Result<()> {
    let path = state_dir.join("state-format.json");
    if path.exists() || pending_publication_path(&path)?.exists() {
        return Err(state_error("state format marker already exists"));
    }
    durable_json(
        &path,
        &StateFormat {
            format_version: STATE_FORMAT_VERSION,
            producer: STATE_PRODUCER.to_owned(),
        },
    )?;
    validate_state_format(state_dir)
}

pub fn validate_state_format(state_dir: &Path) -> Result<()> {
    let path = state_dir.join("state-format.json");
    if pending_publication_path(&path)?.exists() {
        return Err(state_error("pending state format marker is forbidden"));
    }
    let marker: StateFormat = read_json(&path, 4096)
        .map_err(|_| state_error("missing, malformed, or pre-pivot state format marker"))?;
    if marker.format_version != STATE_FORMAT_VERSION || marker.producer != STATE_PRODUCER {
        return Err(state_error("unsupported state format version or producer"));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub schema_version: u32,
    pub authority_id: String,
    pub provider: String,
    pub key_name: String,
    pub scope: String,
    pub algorithm: String,
    pub signature_oid: String,
    pub public_key_sha256: String,
    pub spki_sha256: String,
    pub root_sha256: String,
    pub root_serial: String,
    pub root_subject: String,
    pub root_subject_der_hex: String,
    pub root_ski_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub profile: String,
    pub init_operation_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InitPublication {
    pub schema_version: u32,
    pub operation_id: String,
    pub authority: Authority,
    pub root_der_hex: String,
    pub root_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootSigningIntent {
    pub schema_version: u32,
    pub operation_id: String,
    pub provider: String,
    pub key_name: String,
    pub root_valid_days: u16,
    pub serial: String,
    pub reference_time_unix_seconds: u64,
    pub reference_time_subsec_nanos: u32,
    pub public_blob_hex: String,
    pub public_key_sha256: String,
    pub spki_sha256: String,
    pub tbs_der_hex: String,
    pub tbs_sha256: String,
    pub authority_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InitGeneration {
    pub schema_version: u32,
    pub operation_id: String,
    pub sequence: u32,
    pub phase: InitPhase,
    pub prior_sha256: Option<String>,
    pub provider: String,
    pub key_name: String,
    pub root_valid_days: u16,
    pub utc: String,
    pub ncrypt_status: Option<i32>,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InitPhase {
    Prepared,
    FinalizeStarted,
    FinalizeSucceeded,
    KeyValidated,
    RootSigningPrepared,
    RootValidated,
    AuthorityPublished,
    Completed,
    FinalizeFailed,
    FinalizeUnexpected,
    AbandonVerified,
    Abandoned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SerialReservation {
    pub schema_version: u32,
    pub serial: String,
    pub issuance_id: String,
    pub authority_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuanceIntent {
    pub schema_version: u32,
    pub issuance_id: String,
    pub authority_id: String,
    pub serial: String,
    pub correlation_id: String,
    pub idempotency_key_hash: String,
    pub request_hash: String,
    pub csr_sha256: String,
    pub spki_sha256: String,
    pub dns_sans: Vec<String>,
    pub ip_sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub profile: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuanceRecord {
    pub schema_version: u32,
    pub issuance_id: String,
    pub authority_id: String,
    pub serial: String,
    pub certificate_sha256: String,
    pub certificate_size: usize,
    pub not_before: String,
    pub not_after: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompleteRecord {
    pub schema_version: u32,
    pub issuance_id: String,
    pub authority_id: String,
    pub intent_sha256: String,
    pub certificate_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyRecord {
    pub schema_version: u32,
    pub key_hash: String,
    pub request_hash: String,
    pub issuance_id: String,
    pub certificate_sha256: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuanceCommit {
    pub schema_version: u32,
    pub issuance_id: String,
    pub authority_id: String,
    pub idempotency: IdempotencyRecord,
    pub source_ip: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub prior_sha256: Option<String>,
    pub kind: String,
    pub authority_id: Option<String>,
    pub issuance_id: Option<String>,
    pub operation_id: Option<String>,
    pub source_ip: Option<String>,
    pub outcome: String,
    pub detail: String,
    pub utc: String,
}

pub struct StateLock {
    file: File,
    overlapped: Box<OVERLAPPED>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchResult {
    Changed,
    Timeout,
    Overflow,
}

pub struct DirectoryWatcher {
    directory: File,
    event: HANDLE,
    overlapped: Box<OVERLAPPED>,
    buffer: Box<[u8; 65_536]>,
    armed: bool,
}

// SAFETY: `DirectoryWatcher` uniquely owns its file, event, buffer, and OVERLAPPED
// operation and is moved to exactly one watcher thread before `wait` is called.
unsafe impl Send for DirectoryWatcher {}

impl DirectoryWatcher {
    pub fn register(path: &Path) -> Result<Self> {
        validate_state_dir(path)?;
        Self::open(path)
    }

    pub fn register_replacement(path: &Path) -> Result<Self> {
        validate_state_path_argument(path)?;
        validate_existing_tree(path)?;
        validate_protected_acl(path)?;
        Self::open(path)
    }

    fn open(path: &Path) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED)
            .open(path)
            .map_err(|error| state_error(format!("watch directory open failed: {error}")))?;
        // SAFETY: default security, manual reset, nonsignaled, and no name are valid.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(state_error("CreateEventW for state watcher failed"));
        }
        let mut watcher = Self {
            directory,
            event,
            overlapped: Box::new(OVERLAPPED::default()),
            buffer: Box::new([0; 65_536]),
            armed: false,
        };
        watcher.overlapped.hEvent = event;
        watcher.arm()?;
        Ok(watcher)
    }

    pub fn wait(&mut self, timeout: Duration) -> Result<WatchResult> {
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: the event remains live for this watcher.
        match unsafe { WaitForSingleObject(self.event, milliseconds) } {
            WAIT_TIMEOUT => Ok(WatchResult::Timeout),
            WAIT_OBJECT_0 => {
                let mut transferred = 0;
                // SAFETY: directory and OVERLAPPED are the pair used to arm the request.
                let ok = unsafe {
                    GetOverlappedResult(
                        self.directory.as_raw_handle() as HANDLE,
                        &*self.overlapped,
                        &mut transferred,
                        0,
                    )
                };
                self.armed = false;
                let result = if ok == 0 {
                    let code = unsafe { GetLastError() };
                    if code == ERROR_NOTIFY_ENUM_DIR {
                        WatchResult::Overflow
                    } else if code == ERROR_OPERATION_ABORTED {
                        return Err(state_error("state watcher was unexpectedly cancelled"));
                    } else {
                        return Err(state_error(format!(
                            "state watcher completion failed with Win32 error {code}"
                        )));
                    }
                } else if transferred == 0 {
                    WatchResult::Overflow
                } else {
                    validate_notifications(&self.buffer[..transferred as usize])?;
                    WatchResult::Changed
                };
                // SAFETY: event is live and not used by another operation.
                if unsafe { ResetEvent(self.event) } == 0 {
                    return Err(state_error("ResetEvent for state watcher failed"));
                }
                *self.overlapped = OVERLAPPED::default();
                self.overlapped.hEvent = self.event;
                self.arm()?;
                Ok(result)
            }
            code => Err(state_error(format!(
                "WaitForSingleObject for state watcher failed with {code}"
            ))),
        }
    }

    pub fn wait_with_stop(
        &mut self,
        stop_event: HANDLE,
        timeout: Duration,
    ) -> Result<Option<WatchResult>> {
        let handles = [stop_event, self.event];
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, milliseconds) };
        if result == WAIT_OBJECT_0 {
            return Ok(None);
        }
        if result == WAIT_TIMEOUT {
            return Ok(Some(WatchResult::Timeout));
        }
        if result != WAIT_OBJECT_0 + 1 {
            return Err(state_error(format!(
                "WaitForMultipleObjects for state watcher failed with {result}"
            )));
        }
        self.wait(Duration::ZERO).map(Some)
    }

    fn arm(&mut self) -> Result<()> {
        let filters = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_ATTRIBUTES
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_CREATION
            | FILE_NOTIFY_CHANGE_SECURITY;
        // SAFETY: the directory was opened for overlapped watching, buffer and OVERLAPPED
        // remain pinned in this object until completion or cancellation.
        let ok = unsafe {
            ReadDirectoryChangesW(
                self.directory.as_raw_handle() as HANDLE,
                self.buffer.as_mut_ptr().cast(),
                self.buffer.len() as u32,
                1,
                filters,
                std::ptr::null_mut(),
                &mut *self.overlapped,
                None,
            )
        };
        if ok == 0 {
            return Err(state_error(format!(
                "ReadDirectoryChangesW registration failed with Win32 error {}",
                unsafe { GetLastError() }
            )));
        }
        self.armed = true;
        Ok(())
    }
}

impl Drop for DirectoryWatcher {
    fn drop(&mut self) {
        if self.armed {
            // SAFETY: cancellation targets only this watcher operation.
            unsafe {
                CancelIoEx(self.directory.as_raw_handle() as HANDLE, &*self.overlapped);
            }
        }
        if !self.event.is_null() {
            // SAFETY: this wrapper uniquely owns the event handle.
            unsafe {
                CloseHandle(self.event);
            }
        }
    }
}

fn validate_notifications(bytes: &[u8]) -> Result<()> {
    let mut offset = 0usize;
    loop {
        if bytes.len().saturating_sub(offset) < 12 {
            return Err(state_error(
                "state watcher returned a malformed notification",
            ));
        }
        let next = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| state_error("malformed watcher offset"))?,
        ) as usize;
        let action = u32::from_le_bytes(
            bytes[offset + 4..offset + 8]
                .try_into()
                .map_err(|_| state_error("malformed watcher action"))?,
        );
        let name_bytes = u32::from_le_bytes(
            bytes[offset + 8..offset + 12]
                .try_into()
                .map_err(|_| state_error("malformed watcher name length"))?,
        ) as usize;
        if !matches!(
            action,
            FILE_ACTION_ADDED
                | FILE_ACTION_REMOVED
                | FILE_ACTION_MODIFIED
                | FILE_ACTION_RENAMED_OLD_NAME
                | FILE_ACTION_RENAMED_NEW_NAME
        ) || !name_bytes.is_multiple_of(2)
            || offset
                .checked_add(12 + name_bytes)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(state_error(
                "state watcher returned an invalid notification",
            ));
        }
        if next == 0 {
            return Ok(());
        }
        if next < 12 + name_bytes
            || offset
                .checked_add(next)
                .is_none_or(|end| end >= bytes.len())
        {
            return Err(state_error("state watcher returned an invalid next offset"));
        }
        offset += next;
    }
}

impl StateLock {
    pub fn acquire(state_dir: &Path, create: bool) -> Result<Self> {
        if create {
            create_state_layout(state_dir)?;
        } else {
            validate_state_dir(state_dir)?;
        }
        let lock_path = state_dir.join("authority.lock");
        let file = open_or_create_protected_file(&lock_path)?;
        validate_protected_acl(&lock_path)?;
        let mut overlapped = Box::new(OVERLAPPED::default());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: the file and OVERLAPPED remain live for the lock lifetime.
            let ok = unsafe {
                LockFileEx(
                    file.as_raw_handle() as HANDLE,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut *overlapped,
                )
            };
            if ok != 0 {
                return Ok(Self { file, overlapped });
            }
            let code = unsafe { GetLastError() };
            if code != ERROR_LOCK_VIOLATION && code != ERROR_SHARING_VIOLATION {
                return Err(state_error(format!(
                    "LockFileEx failed with Win32 error {code}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorClass::StateBusy,
                    "authority lock remained unavailable for ten seconds",
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // SAFETY: this object owns the whole-file lock and its OVERLAPPED.
        unsafe {
            UnlockFileEx(
                self.file.as_raw_handle() as HANDLE,
                0,
                u32::MAX,
                u32::MAX,
                &mut *self.overlapped,
            );
        }
    }
}

pub fn validate_state_path_argument(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(state_error("state directory must be absolute"));
    }
    let text = path.as_os_str().to_string_lossy();
    if text.starts_with(r"\\")
        || text.starts_with(r"\\?\")
        || text.starts_with(r"\\.\")
        || text.contains(':') && !text.get(1..3).is_some_and(|value| value == r":\")
    {
        return Err(state_error(
            "UNC, device, ADS, and nonlocal state paths are forbidden",
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(state_error(
            "state path may not contain relative components",
        ));
    }
    Ok(())
}

pub fn create_state_layout(path: &Path) -> Result<()> {
    validate_state_path_argument(path)?;
    if !path.exists() {
        let parent = path
            .parent()
            .ok_or_else(|| state_error("state directory has no parent"))?;
        validate_existing_tree(parent)?;
        create_protected_dir(path)?;
    }
    validate_state_dir(path)?;
    for name in DIRECTORY_NAMES {
        let child = path.join(name);
        if !child.exists() {
            create_protected_dir(&child)?;
        }
        validate_protected_acl(&child)?;
    }
    for child in [
        path.join("init-intents").join("active"),
        path.join("init-intents").join("archive"),
        path.join("init-intents").join("archive").join("completed"),
        path.join("init-intents").join("archive").join("abandoned"),
    ] {
        if !child.exists() {
            create_protected_dir(&child)?;
        }
        validate_protected_acl(&child)?;
    }
    validate_acl_tree(path)?;
    flush_directory(path)?;
    Ok(())
}

pub fn validate_state_dir(path: &Path) -> Result<()> {
    validate_state_path_argument(path)?;
    if !path.is_dir() {
        return Err(state_error("state directory does not exist"));
    }
    validate_existing_tree(path)?;
    validate_acl_tree(path)
}

fn validate_existing_tree(path: &Path) -> Result<()> {
    for current in path.ancestors().filter(|ancestor| ancestor.exists()) {
        let metadata = fs::symlink_metadata(current)
            .map_err(|error| state_error(format!("cannot inspect state path: {error}")))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(state_error("state path contains a reparse point"));
        }
    }
    Ok(())
}

fn validate_acl_tree(path: &Path) -> Result<()> {
    validate_protected_acl(path)?;
    if path.is_dir() {
        for entry in fs::read_dir(path)
            .map_err(|error| state_error(format!("ACL tree enumeration failed: {error}")))?
        {
            let entry =
                entry.map_err(|error| state_error(format!("ACL tree entry failed: {error}")))?;
            let metadata = entry
                .metadata()
                .map_err(|error| state_error(format!("ACL tree metadata failed: {error}")))?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(state_error("state ACL tree contains a reparse point"));
            }
            validate_acl_tree(&entry.path())?;
        }
    }
    Ok(())
}

pub fn create_protected_dir(path: &Path) -> Result<()> {
    maybe_fault(10)?;
    let descriptor = desired_security_descriptor()?;
    let attributes = security_attributes(&descriptor);
    let wide = wide_path(path);
    // SAFETY: the path is terminated and the security descriptor remains live for the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_ALREADY_EXISTS {
            return Err(state_error(format!(
                "protected directory creation failed with Win32 error {code}"
            )));
        }
    }
    maybe_fault(11)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| state_error(format!("protected directory inspection failed: {error}")))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(state_error(
            "protected directory destination is not a plain directory",
        ));
    }
    validate_protected_acl(path)
}

fn open_or_create_protected_file(path: &Path) -> Result<File> {
    let descriptor = desired_security_descriptor()?;
    let attributes = security_attributes(&descriptor);
    let wide = wide_path(path);
    // SAFETY: arguments are valid, path is terminated, and descriptor lives through the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(state_error(format!(
            "protected file open/create failed with Win32 error {}",
            unsafe { GetLastError() }
        )));
    }
    // SAFETY: CreateFileW returned a uniquely owned valid handle.
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    validate_plain_protected_file(path)?;
    Ok(file)
}

fn create_new_protected_file(path: &Path) -> Result<File> {
    let descriptor = desired_security_descriptor()?;
    let attributes = security_attributes(&descriptor);
    let wide = wide_path(path);
    // SAFETY: arguments are valid, path is terminated, and descriptor lives through the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(state_error(format!(
            "protected staging creation failed with Win32 error {}",
            unsafe { GetLastError() }
        )));
    }
    // SAFETY: CreateFileW returned a uniquely owned valid handle.
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    validate_plain_protected_file(path)?;
    Ok(file)
}

fn validate_plain_protected_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| state_error(format!("protected file inspection failed: {error}")))?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(state_error(
            "protected file destination is not a plain file",
        ));
    }
    validate_protected_acl(path)
}

fn security_attributes(descriptor: &LocalDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.pointer,
        bInheritHandle: 0,
    }
}

#[cfg(test)]
fn apply_protected_acl(path: &Path) -> Result<()> {
    let sid = current_user_sid_string()?;
    apply_sddl(
        path,
        &format!("O:{sid}G:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})"),
    )
}

#[cfg(test)]
fn apply_sddl(path: &Path, sddl: &str) -> Result<()> {
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut pointer = std::ptr::null_mut();
    // SAFETY: input is terminated and output receives a LocalAlloc-owned descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut pointer,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || pointer.is_null() {
        return Err(state_error("security descriptor construction failed"));
    }
    let descriptor = LocalDescriptor { pointer };
    let wide = wide_path(path);
    let information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: path is terminated and descriptor is a live self-relative security descriptor.
    let ok = unsafe { SetFileSecurityW(wide.as_ptr(), information, descriptor.pointer) };
    if ok == 0 {
        return Err(state_error(format!(
            "SetFileSecurityW failed with Win32 error {}",
            unsafe { GetLastError() }
        )));
    }
    Ok(())
}

fn validate_protected_acl(path: &Path) -> Result<()> {
    let expected = desired_security_descriptor()?;
    let expected_sddl = descriptor_to_sddl(expected.pointer)?;
    let actual = file_security_descriptor(path)?;
    let actual_sddl = descriptor_to_sddl(actual.as_ptr().cast_mut().cast())?;
    if actual_sddl != expected_sddl {
        return Err(state_error(format!(
            "state ACL is not the exact protected current-user and SYSTEM policy: `{actual_sddl}`"
        )));
    }
    Ok(())
}

struct LocalDescriptor {
    pointer: PSECURITY_DESCRIPTOR,
}

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: the descriptor was allocated by an SDDL conversion API.
            unsafe {
                LocalFree(self.pointer);
            }
        }
    }
}

fn desired_security_descriptor() -> Result<LocalDescriptor> {
    let sid = current_user_sid_string()?;
    let sddl = format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})");
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut pointer = std::ptr::null_mut();
    // SAFETY: input is terminated and output receives a LocalAlloc-owned descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut pointer,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || pointer.is_null() {
        return Err(state_error(format!(
            "security descriptor construction failed with Win32 error {}",
            unsafe { GetLastError() }
        )));
    }
    Ok(LocalDescriptor { pointer })
}

fn current_user_sid_string() -> Result<String> {
    let mut token = std::ptr::null_mut();
    // SAFETY: process pseudo-handle is valid and output receives an owned token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(state_error("OpenProcessToken failed"));
    }
    let token_guard = OwnedHandle(token);
    let mut needed = 0;
    // SAFETY: sizing call with null buffer is documented.
    unsafe {
        GetTokenInformation(
            token_guard.0,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed < std::mem::size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
        return Err(state_error("GetTokenInformation returned an invalid size"));
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: buffer has exactly the requested writable size.
    if unsafe {
        GetTokenInformation(
            token_guard.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(state_error("GetTokenInformation(TokenUser) failed"));
    }
    // SAFETY: the API populated a TOKEN_USER at the start of the aligned allocation.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut string = std::ptr::null_mut();
    // SAFETY: token-owned SID is valid and output is LocalAlloc-owned on success.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut string) } == 0 || string.is_null() {
        return Err(state_error("ConvertSidToStringSidW failed"));
    }
    let value = wide_pointer_to_string(string)?;
    // SAFETY: string was allocated by ConvertSidToStringSidW.
    unsafe {
        LocalFree(string.cast());
    }
    Ok(value)
}

fn file_security_descriptor(path: &Path) -> Result<Vec<u8>> {
    let wide = wide_path(path);
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut needed = 0;
    // SAFETY: sizing call with null descriptor is documented.
    unsafe {
        GetFileSecurityW(
            wide.as_ptr(),
            information,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 || needed > 64 * 1024 {
        return Err(state_error("GetFileSecurityW returned an invalid size"));
    }
    let mut bytes = vec![0u8; needed as usize];
    // SAFETY: output buffer has the requested writable capacity.
    if unsafe {
        GetFileSecurityW(
            wide.as_ptr(),
            information,
            bytes.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(state_error("GetFileSecurityW failed"));
    }
    Ok(bytes)
}

fn descriptor_to_sddl(descriptor: PSECURITY_DESCRIPTOR) -> Result<String> {
    let mut string = std::ptr::null_mut();
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: descriptor is live and output receives a LocalAlloc-owned string.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            information,
            &mut string,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || string.is_null() {
        return Err(state_error("security descriptor string conversion failed"));
    }
    let value = wide_pointer_to_string(string)?;
    // SAFETY: string was allocated by the conversion API.
    unsafe {
        LocalFree(string.cast());
    }
    Ok(value)
}

fn wide_pointer_to_string(pointer: *const u16) -> Result<String> {
    let mut length = 0usize;
    // SAFETY: callers supply terminated strings allocated by Windows.
    unsafe {
        while *pointer.add(length) != 0 {
            length += 1;
            if length > 4096 {
                return Err(state_error("Windows string exceeds policy"));
            }
        }
        String::from_utf16(std::slice::from_raw_parts(pointer, length))
            .map_err(|_| state_error("Windows returned invalid UTF-16"))
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the token handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub fn durable_json<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>> {
    let bytes = canonical_json(value, "JSON")?;
    durable_bytes(path, &bytes)?;
    Ok(bytes)
}

pub fn pending_publication_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| state_error("publication path has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| state_error("publication filename is not valid Unicode"))?;
    Ok(parent.join(format!(".{file_name}.pending")))
}

pub fn read_pending_publication(path: &Path, cap: usize) -> Result<Option<Vec<u8>>> {
    let pending = pending_publication_path(path)?;
    if !pending.exists() {
        return Ok(None);
    }
    validate_plain_protected_file(&pending)?;
    read_bounded(&pending, cap).map(Some)
}

pub fn finalize_pending_publication(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(state_error(
            "pending publication destination already exists",
        ));
    }
    let pending = pending_publication_path(path)?;
    validate_plain_protected_file(&pending)?;
    fs::rename(&pending, path)
        .map_err(|error| state_error(format!("pending publication rename failed: {error}")))?;
    validate_plain_protected_file(path)?;
    flush_directory(
        path.parent()
            .ok_or_else(|| state_error("publication path has no parent"))?,
    )
}

pub fn durable_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    maybe_fault(0)?;
    let parent = path
        .parent()
        .ok_or_else(|| state_error("publication path has no parent"))?;
    validate_existing_tree(parent)?;
    if path.exists() {
        return Err(state_error(
            "non-replacing publication destination already exists",
        ));
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| state_error("publication filename is not valid Unicode"))?;
    let staging = parent.join(format!(".{file_name}.pending"));
    if staging.exists() {
        validate_protected_acl(&staging)?;
        let staged = read_bounded(&staging, bytes.len().max(1))?;
        if staged.is_empty() {
            fs::remove_file(&staging)
                .map_err(|error| state_error(format!("empty staging cleanup failed: {error}")))?;
            flush_directory(parent)?;
        } else if staged != bytes {
            return Err(state_error(
                "existing publication staging file does not match the transaction",
            ));
        }
    }
    if !staging.exists() {
        let mut file = create_new_protected_file(&staging)?;
        maybe_fault(1)?;
        file.write_all(bytes)
            .map_err(|error| state_error(format!("cannot write staging file: {error}")))?;
        maybe_fault(2)?;
        file.sync_all()
            .map_err(|error| state_error(format!("cannot flush staging file: {error}")))?;
        maybe_fault(3)?;
        drop(file);
        maybe_fault(4)?;
    }
    let reopened = read_bounded(&staging, bytes.len().max(1))?;
    maybe_fault(5)?;
    if reopened != bytes {
        return Err(state_error("staging file changed after reopen"));
    }
    maybe_fault(6)?;
    fs::rename(&staging, path)
        .map_err(|error| state_error(format!("non-replacing rename failed: {error}")))?;
    maybe_fault(7)?;
    let final_bytes = read_bounded(path, bytes.len().max(1))?;
    maybe_fault(8)?;
    if final_bytes != bytes {
        return Err(state_error("published file changed after reopen"));
    }
    maybe_fault(9)?;
    flush_directory(parent)?;
    Ok(())
}

#[cfg(not(test))]
#[inline]
fn maybe_fault(_: usize) -> Result<()> {
    Ok(())
}

#[cfg(test)]
fn maybe_fault(point: usize) -> Result<()> {
    test_faults::check(point)
}

#[cfg(test)]
mod test_faults {
    use super::{Error, ErrorClass, Result};
    use std::cell::Cell;

    thread_local! {
        static FAIL_AT: Cell<Option<usize>> = const { Cell::new(None) };
    }

    pub(super) fn set(point: Option<usize>) {
        FAIL_AT.set(point);
    }

    pub(super) fn check(point: usize) -> Result<()> {
        if FAIL_AT.get() == Some(point) {
            return Err(Error::new(
                ErrorClass::State,
                format!("test publication fault at boundary {point}"),
            ));
        }
        Ok(())
    }
}

pub fn read_json<T: DeserializeOwned>(path: &Path, cap: usize) -> Result<T> {
    let bytes = read_bounded(path, cap)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|error| state_error(format!("invalid JSON `{}`: {error}", path.display())))?;
    deserializer
        .end()
        .map_err(|error| state_error(format!("trailing JSON data: {error}")))?;
    Ok(value)
}

pub fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| state_error(format!("cannot inspect `{}`: {error}", path.display())))?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.file_size() as usize > cap
    {
        return Err(state_error("state file type or size violates policy"));
    }
    let mut file = File::open(path)
        .map_err(|error| state_error(format!("cannot open `{}`: {error}", path.display())))?;
    let mut bytes = Vec::with_capacity(metadata.file_size() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| state_error(format!("cannot read state file: {error}")))?;
    if bytes.len() != metadata.file_size() as usize {
        return Err(state_error("state file changed while being read"));
    }
    Ok(bytes)
}

pub fn append_audit(state_dir: &Path, mut record: AuditRecord) -> Result<()> {
    let directory = state_dir.join("audit");
    let mut entries = numbered_json_entries(&directory)?;
    entries.sort();
    record.sequence = entries.len() as u64;
    record.prior_sha256 = entries
        .last()
        .map(|path| read_bounded(path, 64 * 1024))
        .transpose()?
        .map(|bytes| hex(&hash_sha256(&bytes).unwrap_or([0; 32])));
    durable_json(
        &directory.join(format!("{:020}.json", record.sequence)),
        &record,
    )?;
    Ok(())
}

pub fn numbered_json_entries(path: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)
        .map_err(|error| state_error(format!("cannot enumerate `{}`: {error}", path.display())))?
    {
        let entry = entry.map_err(|error| state_error(format!("enumeration failed: {error}")))?;
        if entry
            .file_type()
            .map_err(|error| state_error(format!("entry type failed: {error}")))?
            .is_symlink()
        {
            return Err(state_error("state directory contains a link"));
        }
        let entry_path = entry.path();
        let name = entry_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| state_error("state entry name is not valid Unicode"))?;
        if !name.starts_with('.') || !name.ends_with(".pending") {
            entries.push(entry_path);
        }
    }
    Ok(entries)
}

pub fn pending_entries(path: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)
        .map_err(|error| state_error(format!("cannot enumerate `{}`: {error}", path.display())))?
    {
        let entry = entry.map_err(|error| state_error(format!("enumeration failed: {error}")))?;
        let entry_path = entry.path();
        let name = entry_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| state_error("state entry name is not valid Unicode"))?;
        if name.starts_with('.') && name.ends_with(".pending") {
            entries.push(entry_path);
        }
    }
    entries.sort();
    Ok(entries)
}

pub fn utc_now() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| state_error(format!("UTC formatting failed: {error}")))
}

pub fn parse_utc(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| state_error(format!("invalid RFC3339 UTC time: {error}")))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err(state_error("noncanonical hexadecimal value"));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| state_error("invalid hexadecimal value"))?;
    }
    Ok(output)
}

fn flush_directory(path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| state_error(format!("cannot open parent directory: {error}")))?;
    // SAFETY: the directory handle is live. Some filesystems reject directory flush.
    let ok = unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code != windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE
            && code != windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED
        {
            return Err(state_error(format!(
                "directory flush failed with Win32 error {code}"
            )));
        }
    }
    Ok(())
}

fn state_error(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::State, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_path(label: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("{label}-{}", std::process::id()))
    }

    #[test]
    fn canonical_hex_round_trip() {
        let value = [0x01, 0xab, 0xff];
        assert_eq!(hex(&value), "01abff");
        assert_eq!(
            decode_hex::<3>("01abff").unwrap_or_else(|error| panic!("{error}")),
            value
        );
    }

    #[test]
    fn schemas_reject_unknown_fields() {
        let input = br#"{"schema_version":1,"serial":"01","issuance_id":"00","authority_id":"00","created_at":"x","extra":1}"#;
        assert!(serde_json::from_slice::<SerialReservation>(input).is_err());
    }

    #[test]
    fn watcher_notifications_reject_overflow_like_corruption() {
        let mut valid = Vec::new();
        valid.extend_from_slice(&0u32.to_le_bytes());
        valid.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
        valid.extend_from_slice(&2u32.to_le_bytes());
        valid.extend_from_slice(&('x' as u16).to_le_bytes());
        validate_notifications(&valid).unwrap_or_else(|error| panic!("{error}"));
        valid[8..12].copy_from_slice(&3u32.to_le_bytes());
        assert!(validate_notifications(&valid).is_err());
        assert!(validate_notifications(&[]).is_err());
    }

    #[test]
    fn protected_acl_rejects_an_additional_world_ace() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let path = test_path("acl-policy");
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(
            path.parent()
                .unwrap_or_else(|| panic!("test path has no parent")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        create_state_layout(&path).unwrap_or_else(|error| panic!("{error}"));
        validate_state_dir(&path).unwrap_or_else(|error| panic!("{error}"));
        let sid = current_user_sid_string().unwrap_or_else(|error| panic!("{error}"));
        apply_sddl(
            &path,
            &format!("O:{sid}G:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})(A;OICI;GR;;;WD)"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(validate_state_dir(&path).is_err());
        apply_protected_acl(&path).unwrap_or_else(|error| panic!("{error}"));
        fs::remove_dir_all(&path).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn every_durable_publication_boundary_is_recoverable() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let parent = test_path("publication-faults");
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir_all(&parent).unwrap_or_else(|error| panic!("{error}"));
        apply_protected_acl(&parent).unwrap_or_else(|error| panic!("{error}"));
        for artifact in ["intent.json", "serial-reservation.json"] {
            for point in 0..10 {
                let directory = parent.join(format!("{artifact}-{point}"));
                fs::create_dir(&directory).unwrap_or_else(|error| panic!("{error}"));
                apply_protected_acl(&directory).unwrap_or_else(|error| panic!("{error}"));
                let destination = directory.join(artifact);
                test_faults::set(Some(point));
                assert!(durable_bytes(&destination, b"journal-bound-bytes").is_err());
                test_faults::set(None);
                if destination.exists() {
                    assert_eq!(
                        read_bounded(&destination, 64).unwrap_or_else(|error| panic!("{error}")),
                        b"journal-bound-bytes"
                    );
                } else {
                    durable_bytes(&destination, b"journal-bound-bytes")
                        .unwrap_or_else(|error| panic!("{error}"));
                }
            }
        }
        fs::remove_dir_all(&parent).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn protected_directory_creation_is_atomic_and_restart_safe() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let parent = test_path("atomic-directory");
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir_all(&parent).unwrap_or_else(|error| panic!("{error}"));
        let sid = current_user_sid_string().unwrap_or_else(|error| panic!("{error}"));
        apply_sddl(
            &parent,
            &format!("O:{sid}G:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})(A;OICI;GR;;;WD)"),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let before = parent.join("before");
        test_faults::set(Some(10));
        assert!(create_protected_dir(&before).is_err());
        test_faults::set(None);
        assert!(!before.exists());

        let after = parent.join("after");
        test_faults::set(Some(11));
        assert!(create_protected_dir(&after).is_err());
        test_faults::set(None);
        validate_protected_acl(&after).unwrap_or_else(|error| panic!("{error}"));
        create_protected_dir(&after).unwrap_or_else(|error| panic!("{error}"));
        fs::read_dir(&after).unwrap_or_else(|error| panic!("{error}"));

        fs::remove_dir_all(&parent).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn state_format_is_fresh_only_and_exact() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let path = test_path("state-format");
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(path.parent().unwrap_or_else(|| panic!("missing parent")))
            .unwrap_or_else(|error| panic!("{error}"));
        create_state_layout(&path).unwrap_or_else(|error| panic!("{error}"));
        assert!(validate_state_format(&path).is_err());
        publish_state_format(&path).unwrap_or_else(|error| panic!("{error}"));
        validate_state_format(&path).unwrap_or_else(|error| panic!("{error}"));
        assert!(publish_state_format(&path).is_err());
        fs::write(
            path.join("state-format.json"),
            br#"{"format_version":2,"producer":"azihsm-ca-rcgen-actix-v1"}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(validate_state_format(&path).is_err());
        fs::remove_dir_all(&path).unwrap_or_else(|error| panic!("{error}"));
    }
}
