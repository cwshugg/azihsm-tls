//! Clap command definitions and strict public-input validation.

use azihsm_ca_client::validation::{
    validate_ca_url, validate_cn, validate_dns, validate_ip, validate_key_name,
};
use clap::{Args, Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "azihsm-ca-demo", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Create(CreateArgs),
    Retry(RetryArgs),
    Show(OutputArgs),
    DeleteKey(DeleteKeyArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CreateArgs {
    #[arg(long)]
    pub(crate) output_dir: PathBuf,
    #[arg(long, value_parser = validate_cn)]
    pub(crate) subject_cn: String,
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
pub(crate) struct RetryArgs {
    #[arg(long)]
    pub(crate) output_dir: PathBuf,
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub(crate) acknowledge_plain_http: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OutputArgs {
    #[arg(long)]
    pub(crate) output_dir: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct DeleteKeyArgs {
    #[arg(long)]
    pub(crate) output_dir: PathBuf,
    #[arg(long, value_parser = validate_key_name)]
    pub(crate) confirm_key_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_has_only_p256_workflow_and_requires_http_acknowledgement() {
        assert!(
            Cli::try_parse_from([
                "azihsm-ca-demo",
                "create",
                "--output-dir",
                "C:\\demo",
                "--subject-cn",
                "server",
                "--dns",
                "server.test",
                "--ca-url",
                "http://127.0.0.1:8080"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "azihsm-ca-demo",
                "create",
                "--output-dir",
                "C:\\demo",
                "--subject-cn",
                "server",
                "--dns",
                "server.test",
                "--ca-url",
                "http://127.0.0.1:8080",
                "--acknowledge-plain-http"
            ])
            .is_ok()
        );
    }
}
