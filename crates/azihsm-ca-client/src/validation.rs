//! Strict validation for shared CA client inputs.

use std::net::IpAddr;

const MAX_SANS: usize = 16;

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
}
