// Copyright (C) Microsoft Corporation. All rights reserved.

use clap::{Args, Parser, Subcommand};

const MAX_KEY_NAME: usize = 128;

#[derive(Debug, Parser)]
#[command(name = "keytool", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create and finalize a named P-256 key in AziHSM, then self-test it.
    Init(KeyArgs),
    /// Open an existing named key and sign a challenge (proves cross-process access).
    Open(KeyArgs),
    /// Print the exported public key (hex) of a named key.
    Public(KeyArgs),
    /// Delete a named key.
    Delete(KeyArgs),
}

#[derive(Debug, Args)]
pub struct KeyArgs {
    #[arg(long, value_parser = validate_key_name)]
    pub name: String,
}

fn validate_key_name(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("key name must not be empty".into());
    }
    if value.len() > MAX_KEY_NAME {
        return Err(format!("key name must be at most {MAX_KEY_NAME} bytes"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("key name may only contain [A-Za-z0-9._-]".into());
    }
    Ok(value.to_owned())
}
