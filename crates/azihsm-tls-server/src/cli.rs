//! Command-line contract for TLS serving and identity inspection.

use azihsm_ca_client::validation::{validate_ca_url, validate_dns, validate_ip, validate_key_name};
use clap::{Args, Parser, Subcommand};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "azihsm-tls-server", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Run(RunArgs),
    Show(StateArgs),
    DeleteKey(DeleteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    #[arg(long)]
    pub(crate) state_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8443")]
    pub(crate) listen: SocketAddr,
    #[arg(long = "dns", value_parser = validate_dns)]
    pub(crate) dns: Vec<String>,
    #[arg(long = "ip", value_parser = validate_ip)]
    pub(crate) ip: Vec<IpAddr>,
    #[arg(long, value_parser = validate_ca_url)]
    pub(crate) ca_url: String,
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub(crate) acknowledge_plain_http: bool,
    #[arg(long, value_parser = validate_key_name)]
    pub(crate) key_name: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct StateArgs {
    #[arg(long)]
    pub(crate) state_dir: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct DeleteArgs {
    #[arg(long)]
    pub(crate) state_dir: PathBuf,
    #[arg(long, value_parser = validate_key_name)]
    pub(crate) confirm_key_name: String,
}
