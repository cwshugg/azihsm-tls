//! Command-line contract for TLS serving and identity inspection.

use clap::{Args, Parser, Subcommand};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "azihsm-tls-server", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Run(RunArgs),
    Show(StateArgs),
    DeleteKey(DeleteArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long)]
    pub state_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8443")]
    pub listen: SocketAddr,
    #[arg(long = "dns", value_parser = crate::ca_cli::validate_dns)]
    pub dns: Vec<String>,
    #[arg(long = "ip", value_parser = crate::ca_cli::validate_ip)]
    pub ip: Vec<IpAddr>,
    #[arg(long, value_parser = crate::ca_cli::validate_ca_url)]
    pub ca_url: String,
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub acknowledge_plain_http: bool,
    #[arg(long, value_parser = crate::ca_cli::validate_key_name)]
    pub key_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct StateArgs {
    #[arg(long)]
    pub state_dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    #[arg(long)]
    pub state_dir: PathBuf,
    #[arg(long, value_parser = crate::ca_cli::validate_key_name)]
    pub confirm_key_name: String,
}
