//! Clap command definitions and strict public-input validation.

use clap::{Args, Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;

const MAX_SANS: usize = 16;

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

pub fn validate_sans(dns: &[String], ip: &[IpAddr]) -> Result<(), String> {
    if dns.is_empty() && ip.is_empty() {
        return Err("at least one DNS or IP SAN is required".to_owned());
    }
    if dns.len() + ip.len() > MAX_SANS {
        return Err(format!("no more than {MAX_SANS} SANs are allowed"));
    }
    let mut dns_unique = std::collections::BTreeSet::new();
    if dns
        .iter()
        .any(|value| validate_dns(value).is_err() || !dns_unique.insert(value))
    {
        return Err("duplicate DNS SAN".to_owned());
    }
    let mut ip_unique = std::collections::BTreeSet::new();
    if ip
        .iter()
        .any(|value| value.is_unspecified() || value.is_multicast() || !ip_unique.insert(value))
    {
        return Err("duplicate IP SAN".to_owned());
    }
    Ok(())
}

pub fn validate_cn(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '\0' | '\r' | '\n'))
    {
        return Err("subject CN must contain 1-128 non-control characters".to_owned());
    }
    Ok(value.to_owned())
}

pub fn validate_dns(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 253
        || value.contains('*')
        || value.ends_with('.')
        || value.bytes().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
        })
        || value.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return Err("DNS SAN must be a lowercase ASCII LDH name without wildcards".to_owned());
    }
    Ok(value.to_owned())
}

pub fn validate_ip(value: &str) -> Result<IpAddr, String> {
    let address: IpAddr = value.parse().map_err(|_| "invalid IP SAN".to_owned())?;
    if address.is_unspecified() || address.is_multicast() {
        return Err("unspecified and multicast IP SANs are forbidden".to_owned());
    }
    Ok(address)
}

pub fn validate_key_name(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "key name must contain 1-128 ASCII letters, digits, '.', '_', or '-'".to_owned(),
        );
    }
    Ok(value.to_owned())
}

pub fn validate_ca_url(value: &str) -> Result<String, String> {
    let Some(rest) = value.strip_prefix("http://") else {
        return Err("CA URL must use explicit http://".to_owned());
    };
    if rest.is_empty()
        || rest
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || rest.contains(['?', '#'])
        || rest
            .split('/')
            .next()
            .is_some_and(|authority| authority.is_empty() || authority.contains('@'))
        || rest.find('/').is_some_and(|index| index + 1 != rest.len())
    {
        return Err("CA URL must be an HTTP origin without credentials, query, or path".to_owned());
    }
    Ok(value.trim_end_matches('/').to_owned())
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
