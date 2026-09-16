//! Reparse-safe, non-overwriting artifact publication shared by client applications.

use crate::{Error, ErrorClass, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FlushFileBuffers,
};

const JSON_LIMIT: u64 = 64 * 1024;

pub fn create_output_dir(path: &Path) -> Result<()> {
    validate_path_argument(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| state("output directory has no parent"))?;
    validate_existing_ancestors(parent)?;
    fs::create_dir(path)
        .map_err(|error| state(format!("cannot create output directory: {error}")))?;
    validate_directory(path)?;
    flush_directory(parent)
}

pub fn validate_output_dir(path: &Path) -> Result<()> {
    validate_path_argument(path)?;
    validate_existing_ancestors(path)?;
    validate_directory(path)?;
    for entry in fs::read_dir(path)
        .map_err(|error| state(format!("cannot list output directory: {error}")))?
    {
        let entry =
            entry.map_err(|error| state(format!("cannot inspect output entry: {error}")))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| state(format!("cannot inspect output entry: {error}")))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(state("output directory contains a reparse point"));
        }
    }
    Ok(())
}

pub fn is_empty(path: &Path) -> Result<bool> {
    for entry in fs::read_dir(path)
        .map_err(|error| state(format!("cannot list output directory: {error}")))?
    {
        let entry = entry.map_err(|error| state(format!("cannot inspect output: {error}")))?;
        if entry.file_name() != crate::state_lock::STATE_LOCK_FILE {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    stage(path, bytes)?;
    commit_staged(path, bytes)
}

pub fn stage_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    stage(path, &json_bytes(value)?)
}

pub fn commit_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    commit_staged(path, &json_bytes(value)?)
}

fn stage(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| state("artifact has no parent"))?;
    validate_output_dir(parent)?;
    if path.exists() {
        let existing = read_bounded(path, bytes.len().saturating_add(1) as u64)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(state("artifact already exists with different bytes"));
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| state("artifact name is not Unicode"))?;
    let staging = parent.join(format!(".{name}.pending"));
    if staging.exists() {
        validate_plain_file(&staging)?;
        let staged = read_bounded(&staging, bytes.len().saturating_add(1) as u64)?;
        if staged.is_empty() {
            fs::remove_file(&staging)
                .map_err(|error| state(format!("cannot remove empty staging file: {error}")))?;
        } else if staged != bytes {
            return Err(state(
                "artifact staging file differs from the requested bytes",
            ));
        }
    }
    if !staging.exists() {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|error| state(format!("cannot create artifact staging file: {error}")))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| state(format!("cannot flush artifact staging file: {error}")))?;
        drop(file);
    }
    validate_plain_file(&staging)?;
    if read_bounded(&staging, bytes.len().saturating_add(1) as u64)? != bytes {
        return Err(state("artifact staging changed after flush"));
    }
    Ok(())
}

fn commit_staged(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| state("artifact has no parent"))?;
    validate_output_dir(parent)?;
    if path.exists() {
        let existing = read_bounded(path, bytes.len().saturating_add(1) as u64)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(state("artifact already exists with different bytes"));
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| state("artifact name is not Unicode"))?;
    let staging = parent.join(format!(".{name}.pending"));
    validate_plain_file(&staging)?;
    if read_bounded(&staging, bytes.len().saturating_add(1) as u64)? != bytes {
        return Err(state("artifact staging changed before publication"));
    }
    fs::rename(&staging, path).map_err(|error| {
        state(format!(
            "cannot publish artifact without replacement: {error}"
        ))
    })?;
    validate_plain_file(path)?;
    flush_directory(parent)
}

pub fn publish_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    publish(path, &json_bytes(value)?)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_bounded(path, JSON_LIMIT)?)
        .map_err(|error| state(format!("cannot parse metadata: {error}")))
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    validate_plain_file(path)?;
    let mut file =
        File::open(path).map_err(|error| state(format!("cannot open artifact: {error}")))?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| state(format!("cannot read artifact: {error}")))?;
    if bytes.len() as u64 > limit {
        return Err(state("artifact exceeds size limit"));
    }
    Ok(bytes)
}

pub fn remove(path: &Path) -> Result<()> {
    validate_plain_file(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| state("artifact has no parent"))?;
    fs::remove_file(path)
        .map_err(|error| state(format!("cannot remove staging record: {error}")))?;
    flush_directory(parent)
}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| state(format!("cannot encode metadata: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_path_argument(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || text.starts_with("\\\\")
        || text
            .char_indices()
            .any(|(index, character)| character == ':' && index != 1)
    {
        return Err(state(
            "output directory must be an absolute local Windows path",
        ));
    }
    Ok(())
}

fn validate_existing_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors().filter(|ancestor| ancestor.exists()) {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| state(format!("cannot inspect output path: {error}")))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(state("output path contains a reparse point"));
        }
    }
    Ok(())
}

fn validate_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| state(format!("cannot inspect output directory: {error}")))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(state("output destination is not a plain directory"));
    }
    Ok(())
}

fn validate_plain_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| state(format!("cannot inspect artifact: {error}")))?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(state("artifact is not a plain file"));
    }
    Ok(())
}

fn flush_directory(path: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| state(format!("cannot open artifact directory: {error}")))?;
    // SAFETY: the directory handle remains live for the duration of the call.
    let ok = unsafe { FlushFileBuffers(directory.as_raw_handle().cast()) };
    if ok == 0 {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if code != windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE
            && code != windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED
        {
            return Err(state(format!(
                "cannot flush artifact directory: Win32 error {code}"
            )));
        }
    }
    Ok(())
}

fn state(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::State, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_is_non_replacing_and_idempotent_for_exact_bytes() {
        let directory = std::env::current_dir()
            .unwrap_or_else(|error| panic!("{error}"))
            .join("target")
            .join(format!("client-files-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(
            directory
                .parent()
                .unwrap_or_else(|| panic!("test path has no parent")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        create_output_dir(&directory).unwrap_or_else(|error| panic!("{error}"));
        let path = directory.join("artifact.der");
        publish(&path, b"first").unwrap_or_else(|error| panic!("{error}"));
        publish(&path, b"first").unwrap_or_else(|error| panic!("{error}"));
        assert!(publish(&path, b"second").is_err());
        assert_eq!(
            fs::read(&path).unwrap_or_else(|error| panic!("{error}")),
            b"first"
        );
        fs::remove_dir_all(directory).unwrap_or_else(|error| panic!("{error}"));
    }
}
