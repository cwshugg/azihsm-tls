// Copyright (C) Microsoft Corporation. All rights reserved.

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "azihsm-tls-client", version, about)]
pub struct Cli {
    /// Server address to connect to, as host:port.
    #[arg(long, value_parser = validate_authority)]
    pub connect: String,
    /// PEM file containing the CA root certificate to trust as the only anchor.
    #[arg(long)]
    pub ca_root: PathBuf,
    /// Expected server name (SNI and certificate validation).
    #[arg(long, value_parser = validate_server_name)]
    pub server_name: String,
    /// Message to send after the handshake.
    #[arg(long, default_value = "hello from azihsm-tls-client")]
    pub message: String,
}

fn validate_authority(value: &str) -> Result<String, String> {
    let (host, port) = value.rsplit_once(':').ok_or("connect must be host:port")?;
    if host.is_empty() {
        return Err("host must not be empty".into());
    }
    port.parse::<u16>()
        .map_err(|_| "port must be 1..=65535".to_owned())?;
    Ok(value.to_owned())
}

fn validate_server_name(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("server name must not be empty".into());
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("server name must not contain whitespace or control characters".into());
    }
    Ok(value.to_owned())
}
