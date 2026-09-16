//! Clap command definitions and strict public-input validation.

pub use azihsm_ca_client::validation::{
    validate_ca_url, validate_cn, validate_dns, validate_ip, validate_key_name, validate_sans,
};
use clap::{Args, Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "azihsm-ca-demo", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Create(CreateArgs),
    Retry(RetryArgs),
    Show(OutputArgs),
    DeleteKey(DeleteKeyArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[arg(long)]
    pub output_dir: PathBuf,
    #[arg(long, value_parser = validate_cn)]
    pub subject_cn: String,
    #[arg(long = "dns", value_parser = validate_dns)]
    pub dns: Vec<String>,
    #[arg(long = "ip", value_parser = validate_ip)]
    pub ip: Vec<IpAddr>,
    #[arg(long, value_parser = validate_ca_url)]
    pub ca_url: String,
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub acknowledge_plain_http: bool,
    #[arg(long, value_parser = validate_key_name)]
    pub key_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct RetryArgs {
    #[arg(long)]
    pub output_dir: PathBuf,
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub acknowledge_plain_http: bool,
}

#[derive(Debug, Args)]
pub struct OutputArgs {
    #[arg(long)]
    pub output_dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct DeleteKeyArgs {
    #[arg(long)]
    pub output_dir: PathBuf,
    #[arg(long, value_parser = validate_key_name)]
    pub confirm_key_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn rejects_missing_duplicate_and_wildcard_sans() {
        assert!(validate_sans(&[], &[]).is_err());
        assert!(validate_dns("*.example.test").is_err());
        assert!(validate_dns("UPPER.example").is_err());
        assert!(validate_sans(&["a.test".into(), "a.test".into()], &[]).is_err());
        assert!(
            validate_sans(
                &[],
                &["192.0.2.1".parse().unwrap(), "192.0.2.1".parse().unwrap()]
            )
            .is_err()
        );
    }

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
