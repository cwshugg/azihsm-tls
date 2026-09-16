// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ncrypt::{AzihsmKey, AzihsmProvider, Error, ErrorClass, PROVIDER_NAME, Result};

/// Create a named key, finalize it, and run a sign/verify self-test.
pub fn init(name: &str) -> Result<()> {
    let provider = AzihsmProvider::open_named(PROVIDER_NAME)?;
    provider.require_absent(name)?;
    let key = provider.create_named_staged(name)?;
    let status = key.finalize();
    if status < 0 {
        return Err(status_error("NCryptFinalizeKey", status));
    }
    // The key is now persisted; delete it if the self-test fails so re-runs stay clean.
    let blob = match key.kat().and_then(|()| key.public_blob()) {
        Ok(blob) => blob,
        Err(error) => {
            let _ = key.delete();
            return Err(error);
        }
    };
    tracing::info!(event = "key_initialized", name);
    println!("created named key '{name}'");
    println!("public: {}", hex(&blob));
    Ok(())
}

/// Open an existing named key and sign a fresh challenge through AziHSM.
pub fn open(name: &str) -> Result<()> {
    let key = open_key(name)?;
    key.kat()?;
    println!("opened named key '{name}' and signed a challenge (cross-process OK)");
    Ok(())
}

/// Print the exported public key of a named key as hex.
pub fn public(name: &str) -> Result<()> {
    let key = open_key(name)?;
    println!("{}", hex(&key.public_blob()?));
    Ok(())
}

/// Delete a named key.
pub fn delete(name: &str) -> Result<()> {
    open_key(name)?.delete()?;
    println!("deleted named key '{name}'");
    Ok(())
}

fn open_key(name: &str) -> Result<AzihsmKey> {
    let provider = AzihsmProvider::open_named(PROVIDER_NAME)?;
    provider
        .open_key(name)
        .map_err(|status| status_error("NCryptOpenKey", status))
}

fn status_error(operation: &str, status: i32) -> Error {
    Error::new(
        ErrorClass::Provider,
        format!("{operation} failed with status 0x{:08x}", status as u32),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
