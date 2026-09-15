//! Strict, dependency-free command-line parsing.

use crate::error::{Error, ErrorClass, Result};
use crate::policy::{PROVIDER_NAME, warning_text};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
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

pub fn help() -> String {
    format!(
        "azihsm-ca - persistent Windows-only demonstration CA\n\n{}\
USAGE:\n\
  azihsm-ca --help\n\
  azihsm-ca init --state-dir ABSOLUTE_PATH --provider \"{PROVIDER_NAME}\" --key-name NAME [--root-valid-days 3650]\n\
  azihsm-ca init --state-dir ABSOLUTE_PATH --reconcile-intent HEX32\n\
  azihsm-ca init --state-dir ABSOLUTE_PATH --abandon-intent HEX32\n\
  azihsm-ca serve --state-dir ABSOLUTE_PATH [--listen 127.0.0.1:8080] --allow-dns NAME... --allow-ip ADDRESS... [OPTIONS]\n\
  azihsm-ca inspect --state-dir ABSOLUTE_PATH\n\
  azihsm-ca quarantine-issuance --state-dir ABSOLUTE_PATH --issuance-id HEX32\n\n\
Exit codes: 0 success, 2 usage, 3 state, 4 provider/key, 5 pending recovery,\n\
6 identity/profile/crypto, 7 HTTP runtime, 8 issuance/durability,\n\
9 reserved (not emitted by this version), 10 initialized, 11 busy, 12 refused.\n",
        warning_text()
    )
}

pub fn parse<I>(arguments: I) -> Result<Command>
where
    I: IntoIterator<Item = OsString>,
{
    let mut values = arguments.into_iter();
    let _program = values.next();
    let rest: Vec<OsString> = values.collect();
    if rest.len() == 1 && rest[0] == OsStr::new("--help") {
        return Ok(Command::Help);
    }
    let command = text(
        rest.first().ok_or_else(|| usage_error("missing command"))?,
        "command",
    )?;
    let options = &rest[1..];
    match command {
        "init" => parse_init(options),
        "serve" => parse_serve(options),
        "inspect" => parse_inspect(options),
        "quarantine-issuance" => parse_quarantine(options),
        _ => usage(format!("unknown command `{command}`")),
    }
}

fn parse_init(values: &[OsString]) -> Result<Command> {
    let pairs = option_pairs(values)?;
    let state_dir = required_path(&pairs, "--state-dir")?;
    let provider = optional_text(&pairs, "--provider")?;
    let key_name = optional_text(&pairs, "--key-name")?;
    let root_days = optional_text(&pairs, "--root-valid-days")?;
    let reconcile = optional_text(&pairs, "--reconcile-intent")?;
    let abandon = optional_text(&pairs, "--abandon-intent")?;
    reject_unknown(
        &pairs,
        &[
            "--state-dir",
            "--provider",
            "--key-name",
            "--root-valid-days",
            "--reconcile-intent",
            "--abandon-intent",
        ],
    )?;
    let mode = match (reconcile, abandon) {
        (Some(_), Some(_)) => return usage("reconcile and abandon are mutually exclusive"),
        (Some(id), None) => {
            if provider.is_some() || key_name.is_some() || root_days.is_some() {
                return usage("reconcile accepts only state-dir and operation ID");
            }
            InitMode::Reconcile {
                operation_id: hex32(&id, "operation ID")?,
            }
        }
        (None, Some(id)) => {
            if provider.is_some() || key_name.is_some() || root_days.is_some() {
                return usage("abandon accepts only state-dir and operation ID");
            }
            InitMode::Abandon {
                operation_id: hex32(&id, "operation ID")?,
            }
        }
        (None, None) => {
            let provider = provider.ok_or_else(|| usage_error("missing `--provider`"))?;
            if provider != PROVIDER_NAME {
                return usage("provider must exactly match the registered AziHSM provider");
            }
            let key_name = key_name.ok_or_else(|| usage_error("missing `--key-name`"))?;
            validate_key_name(&key_name)?;
            let root_valid_days = parse_range(root_days.as_deref().unwrap_or("3650"), 30, 3650)?;
            InitMode::Fresh {
                provider,
                key_name,
                root_valid_days,
            }
        }
    };
    Ok(Command::Init(InitArgs { state_dir, mode }))
}

fn parse_serve(values: &[OsString]) -> Result<Command> {
    let pairs = option_pairs_with_repeats(values, &["--allow-dns", "--allow-ip"])?;
    reject_unknown(
        &pairs,
        &[
            "--state-dir",
            "--listen",
            "--allow-dns",
            "--allow-ip",
            "--leaf-valid-hours",
            "--max-connections",
            "--max-request-body-bytes",
            "--per-source-enrollments-per-minute",
            "--global-enrollments-per-minute",
            "--allow-insecure-demo-http-nonloopback",
        ],
    )?;
    let state_dir = required_path(&pairs, "--state-dir")?;
    let listen_text =
        optional_text(&pairs, "--listen")?.unwrap_or_else(|| "127.0.0.1:8080".to_owned());
    let listen: SocketAddr = listen_text
        .parse()
        .map_err(|_| usage_error("listen must be a canonical numeric IP socket address"))?;
    if listen.ip().is_unspecified() || listen.ip().is_multicast() {
        return usage("unspecified and multicast listen addresses are forbidden");
    }
    if listen.ip().to_string() != listen_text.rsplit_once(':').map_or("", |v| v.0)
        && !listen_text.starts_with('[')
    {
        return usage("listen address must be canonical");
    }
    let acknowledgement = flag(&pairs, "--allow-insecure-demo-http-nonloopback")?;
    if !listen.ip().is_loopback() && !acknowledgement {
        return usage("non-loopback listen requires explicit insecure HTTP acknowledgement");
    }
    let mut allow_dns = Vec::new();
    let mut dns_seen = BTreeSet::new();
    for value in all_text(&pairs, "--allow-dns")? {
        validate_dns(&value)?;
        if !dns_seen.insert(value.clone()) {
            return usage("duplicate DNS allowlist entry");
        }
        allow_dns.push(value);
    }
    let mut allow_ip = Vec::new();
    let mut ip_seen = BTreeSet::new();
    for value in all_text(&pairs, "--allow-ip")? {
        let address: IpAddr = value
            .parse()
            .map_err(|_| usage_error("invalid IP allowlist entry"))?;
        if address.to_string() != value || address.is_unspecified() || address.is_multicast() {
            return usage("IP allowlist entries must be canonical unicast addresses");
        }
        if !ip_seen.insert(address) {
            return usage("duplicate IP allowlist entry");
        }
        allow_ip.push(address);
    }
    if allow_dns.is_empty() && allow_ip.is_empty() {
        return usage("at least one DNS or IP SAN must be allowlisted");
    }
    Ok(Command::Serve(ServeArgs {
        state_dir,
        listen,
        allow_dns,
        allow_ip,
        leaf_valid_hours: numeric_option(&pairs, "--leaf-valid-hours", 24, 1, 168)?,
        max_connections: numeric_option(&pairs, "--max-connections", 16, 1, 64)?,
        max_request_body_bytes: numeric_option(
            &pairs,
            "--max-request-body-bytes",
            16_384,
            1,
            16_384,
        )?,
        per_source_per_minute: numeric_option(
            &pairs,
            "--per-source-enrollments-per-minute",
            10,
            1,
            600,
        )?,
        global_per_minute: numeric_option(&pairs, "--global-enrollments-per-minute", 60, 1, 3600)?,
        insecure_nonloopback_acknowledged: acknowledgement,
    }))
}

fn parse_inspect(values: &[OsString]) -> Result<Command> {
    let pairs = option_pairs(values)?;
    reject_unknown(&pairs, &["--state-dir"])?;
    Ok(Command::Inspect {
        state_dir: required_path(&pairs, "--state-dir")?,
    })
}

fn parse_quarantine(values: &[OsString]) -> Result<Command> {
    let pairs = option_pairs(values)?;
    reject_unknown(&pairs, &["--state-dir", "--issuance-id"])?;
    Ok(Command::Quarantine {
        state_dir: required_path(&pairs, "--state-dir")?,
        issuance_id: hex32(
            &optional_text(&pairs, "--issuance-id")?
                .ok_or_else(|| usage_error("missing `--issuance-id`"))?,
            "issuance ID",
        )?,
    })
}

type Pairs = Vec<(String, Option<OsString>)>;

fn option_pairs(values: &[OsString]) -> Result<Pairs> {
    option_pairs_with_repeats(values, &[])
}

fn option_pairs_with_repeats(values: &[OsString], repeats: &[&str]) -> Result<Pairs> {
    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    let mut index = 0;
    while index < values.len() {
        let option = text(&values[index], "option")?;
        if option == "--" || !option.starts_with("--") {
            return usage("bare arguments, short options, and `--` are rejected");
        }
        if !repeats.contains(&option) && !seen.insert(option.to_owned()) {
            return usage(format!("duplicate option `{option}`"));
        }
        if option == "--allow-insecure-demo-http-nonloopback" {
            output.push((option.to_owned(), None));
            index += 1;
            continue;
        }
        let value = values
            .get(index + 1)
            .ok_or_else(|| usage_error(format!("missing value for `{option}`")))?;
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
            return usage(format!("invalid value for `{option}`"));
        }
        reject_nul(value)?;
        output.push((option.to_owned(), Some(value.clone())));
        index += 2;
    }
    Ok(output)
}

fn reject_unknown(pairs: &Pairs, allowed: &[&str]) -> Result<()> {
    if let Some((name, _)) = pairs
        .iter()
        .find(|(name, _)| !allowed.contains(&name.as_str()))
    {
        return usage(format!("unknown option `{name}`"));
    }
    Ok(())
}

fn required_path(pairs: &Pairs, name: &str) -> Result<PathBuf> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| value.clone())
        .map(PathBuf::from)
        .ok_or_else(|| usage_error(format!("missing `{name}`")))
}

fn optional_text(pairs: &Pairs, name: &str) -> Result<Option<String>> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| value.as_ref())
        .map(|value| text(value, name).map(str::to_owned))
        .transpose()
}

fn all_text(pairs: &Pairs, name: &str) -> Result<Vec<String>> {
    pairs
        .iter()
        .filter(|(key, _)| key == name)
        .filter_map(|(_, value)| value.as_ref())
        .map(|value| text(value, name).map(str::to_owned))
        .collect()
}

fn flag(pairs: &Pairs, name: &str) -> Result<bool> {
    Ok(pairs
        .iter()
        .any(|(key, value)| key == name && value.is_none()))
}

fn numeric_option<T>(pairs: &Pairs, name: &str, default: T, min: T, max: T) -> Result<T>
where
    T: Copy + Ord + std::str::FromStr,
{
    match optional_text(pairs, name)? {
        Some(value) => parse_range(&value, min, max),
        None => Ok(default),
    }
}

fn parse_range<T>(value: &str, min: T, max: T) -> Result<T>
where
    T: Copy + Ord + std::str::FromStr,
{
    if value.len() > 1 && value.starts_with('0') || !value.bytes().all(|v| v.is_ascii_digit()) {
        return usage("numeric values must use canonical decimal form");
    }
    let parsed = value
        .parse()
        .map_err(|_| usage_error("numeric value is invalid"))?;
    if parsed < min || parsed > max {
        return usage("numeric value is outside the permitted range");
    }
    Ok(parsed)
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
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || !value.is_ascii()
        || value.bytes().any(|v| v.is_ascii_uppercase())
    {
        return usage("DNS names must be lowercase canonical ASCII LDH names");
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || v == b'-')
        {
            return usage("DNS names must contain valid LDH labels");
        }
    }
    Ok(())
}

fn hex32(value: &str, label: &str) -> Result<String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return usage(format!(
            "{label} must be exactly 32 lowercase hexadecimal digits"
        ));
    }
    Ok(value.to_owned())
}

fn text<'a>(value: &'a OsStr, label: &str) -> Result<&'a str> {
    value
        .to_str()
        .ok_or_else(|| usage_error(format!("{label} is not valid Unicode")))
}

fn reject_nul(value: &OsStr) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    if value.encode_wide().any(|unit| unit == 0) {
        return usage("argument contains a NUL code unit");
    }
    Ok(())
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

    fn args(values: &[&str]) -> Vec<OsString> {
        std::iter::once("azihsm-ca")
            .chain(values.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn parses_fresh_init() {
        let command = parse(args(&[
            "init",
            "--state-dir",
            r"C:\ca",
            "--provider",
            PROVIDER_NAME,
            "--key-name",
            "root-v1",
        ]));
        assert!(matches!(command, Ok(Command::Init(_))));
    }

    #[test]
    fn rejects_nonloopback_without_acknowledgement() {
        let command = parse(args(&[
            "serve",
            "--state-dir",
            r"C:\ca",
            "--listen",
            "10.0.0.4:8080",
            "--allow-dns",
            "server.test",
        ]));
        assert!(command.is_err());
    }

    #[test]
    fn help_contains_every_accepted_risk_and_reserved_exit() {
        let output = help();
        for risk in crate::policy::ACCEPTED_RISKS {
            assert!(output.contains(risk));
        }
        assert!(output.contains("9 reserved"));
    }
}
