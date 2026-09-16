//! Derive-based command-line contract and semantic validation.

use crate::error::{Error, ErrorClass, Result};
use crate::policy::{PROVIDER_NAME, warning_text};
use clap::{ArgGroup, Args, Parser, Subcommand};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "azihsm-ca",
    about = "Persistent Windows-only AziHSM demonstration CA",
    long_about = warning_text(),
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    Init(InitCli),
    #[command(long_about = warning_text())]
    Serve(ServeCli),
    Inspect(StateOnly),
    QuarantineIssuance(QuarantineCli),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("mode")
        .args(["provider", "reconcile_intent", "abandon_intent"])
        .required(true)
        .multiple(false)
))]
struct InitCli {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long, requires = "key_name")]
    provider: Option<String>,
    #[arg(long, requires = "provider")]
    key_name: Option<String>,
    #[arg(long, default_value_t = 3650, requires = "provider")]
    root_valid_days: u16,
    #[arg(long)]
    reconcile_intent: Option<String>,
    #[arg(long)]
    abandon_intent: Option<String>,
}

#[derive(Debug, Args)]
struct ServeCli {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[arg(long, value_parser = parse_dns)]
    allow_dns: Vec<String>,
    #[arg(long)]
    allow_ip: Vec<IpAddr>,
    #[arg(long, default_value_t = 1)]
    leaf_validity_days: u16,
    #[arg(long, default_value_t = 16)]
    max_connections: u8,
    #[arg(long)]
    allow_insecure_demo_http_nonloopback: bool,
}

#[derive(Debug, Args)]
struct StateOnly {
    #[arg(long)]
    state_dir: PathBuf,
}

#[derive(Debug, Args)]
struct QuarantineCli {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long, value_parser = parse_hex32)]
    issuance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help(String),
    Init(InitArgs),
    Serve(ServeArgs),
    Inspect {
        state_dir: PathBuf,
    },
    Quarantine {
        state_dir: PathBuf,
        issuance_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitMode {
    Fresh {
        provider: String,
        key_name: String,
        root_valid_days: u16,
    },
    Reconcile {
        operation_id: String,
    },
    Abandon {
        operation_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    pub state_dir: PathBuf,
    pub mode: InitMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeArgs {
    pub state_dir: PathBuf,
    pub listen: SocketAddr,
    pub allow_dns: Vec<String>,
    pub allow_ip: Vec<IpAddr>,
    pub leaf_valid_hours: u16,
    pub max_connections: u8,
    pub max_request_body_bytes: usize,
    pub per_source_per_minute: u16,
    pub global_per_minute: u16,
    pub insecure_nonloopback_acknowledged: bool,
}

pub fn parse<I>(arguments: I) -> Result<Command>
where
    I: IntoIterator<Item = OsString>,
{
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(Command::Help(format!(
                "{}\nExit codes: 0 success, 2 usage, 3 state, 4 provider/key, 5 pending recovery, \
6 identity/profile/crypto, 7 HTTP runtime, 8 issuance/durability, 9 reserved, \
10 initialized, 11 busy, 12 refused.\n",
                error
            )));
        }
        Err(error) => return Err(Error::new(ErrorClass::Usage, error.to_string())),
    };
    convert(cli.command)
}

fn convert(command: CliCommand) -> Result<Command> {
    match command {
        CliCommand::Init(args) => init(args),
        CliCommand::Serve(args) => serve(args),
        CliCommand::Inspect(args) => Ok(Command::Inspect {
            state_dir: args.state_dir,
        }),
        CliCommand::QuarantineIssuance(args) => Ok(Command::Quarantine {
            state_dir: args.state_dir,
            issuance_id: args.issuance_id,
        }),
    }
}

fn init(args: InitCli) -> Result<Command> {
    if !(30..=3650).contains(&args.root_valid_days) {
        return usage("root validity must be between 30 and 3650 days");
    }
    let mode = if let Some(operation_id) = args.reconcile_intent {
        InitMode::Reconcile {
            operation_id: parse_hex32(&operation_id).map_err(usage_error)?,
        }
    } else if let Some(operation_id) = args.abandon_intent {
        InitMode::Abandon {
            operation_id: parse_hex32(&operation_id).map_err(usage_error)?,
        }
    } else {
        let provider = args
            .provider
            .ok_or_else(|| usage_error("missing provider"))?;
        if provider != PROVIDER_NAME {
            return usage("provider must exactly match the registered AziHSM provider");
        }
        let key_name = args
            .key_name
            .ok_or_else(|| usage_error("missing key name"))?;
        validate_key_name(&key_name)?;
        InitMode::Fresh {
            provider,
            key_name,
            root_valid_days: args.root_valid_days,
        }
    };
    Ok(Command::Init(InitArgs {
        state_dir: args.state_dir,
        mode,
    }))
}

fn serve(args: ServeCli) -> Result<Command> {
    if args.listen.ip().is_unspecified() || args.listen.ip().is_multicast() {
        return usage("unspecified and multicast listen addresses are forbidden");
    }
    if !args.listen.ip().is_loopback() && !args.allow_insecure_demo_http_nonloopback {
        return usage("non-loopback listen requires explicit insecure HTTP acknowledgement");
    }
    if !(1..=7).contains(&args.leaf_validity_days) || !(1..=64).contains(&args.max_connections) {
        return usage("leaf validity or connection count is outside the permitted range");
    }
    let dns = args.allow_dns.into_iter().collect::<BTreeSet<_>>();
    let ips = args.allow_ip.into_iter().collect::<BTreeSet<_>>();
    if dns.is_empty() && ips.is_empty() {
        return usage("at least one DNS or IP SAN must be allowlisted");
    }
    if ips
        .iter()
        .any(|ip| ip.is_unspecified() || ip.is_multicast())
    {
        return usage("IP allowlist entries must be canonical unicast addresses");
    }
    Ok(Command::Serve(ServeArgs {
        state_dir: args.state_dir,
        listen: args.listen,
        allow_dns: dns.into_iter().collect(),
        allow_ip: ips.into_iter().collect(),
        leaf_valid_hours: args.leaf_validity_days * 24,
        max_connections: args.max_connections,
        max_request_body_bytes: 16_384,
        per_source_per_minute: 10,
        global_per_minute: 60,
        insecure_nonloopback_acknowledged: args.allow_insecure_demo_http_nonloopback,
    }))
}

fn validate_key_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'.' | b'_' | b'-'))
    {
        return usage("key name must be 1-128 ASCII letters, digits, dot, underscore, or hyphen");
    }
    Ok(())
}

pub fn validate_dns(value: &str) -> Result<()> {
    parse_dns(value).map(|_| ()).map_err(usage_error)
}

fn parse_dns(value: &str) -> std::result::Result<String, String> {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || !value.is_ascii()
        || value.bytes().any(|v| v.is_ascii_uppercase())
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || v == b'-')
        })
    {
        return Err("DNS names must be lowercase canonical ASCII LDH names".to_owned());
    }
    Ok(value.to_owned())
}

fn parse_hex32(value: &str) -> std::result::Result<String, String> {
    if value.len() == 32
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        Ok(value.to_owned())
    } else {
        Err("value must be exactly 32 lowercase hexadecimal digits".to_owned())
    }
}

fn usage_error(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::Usage, message)
}

fn usage<T>(message: impl Into<String>) -> Result<T> {
    Err(usage_error(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fresh_init() {
        let command = parse(
            [
                "azihsm-ca",
                "init",
                "--state-dir",
                r"C:\ca",
                "--provider",
                PROVIDER_NAME,
                "--key-name",
                "root-v2",
            ]
            .into_iter()
            .map(OsString::from),
        );
        assert!(matches!(command, Ok(Command::Init(_))));
    }

    #[test]
    fn help_contains_every_accepted_risk() {
        let error = Cli::try_parse_from(["azihsm-ca", "--help"])
            .unwrap_err()
            .to_string();
        for risk in crate::policy::ACCEPTED_RISKS {
            assert!(error.contains(risk));
        }
    }
}
