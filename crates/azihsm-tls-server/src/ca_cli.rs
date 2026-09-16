//! Internal enrollment inputs and strict public-input validation.

pub use azihsm_ca_client::validation::{
    validate_ca_url, validate_dns, validate_ip, validate_key_name, validate_sans,
};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug)]
pub struct CreateArgs {
    pub output_dir: PathBuf,
    pub subject_cn: String,
    pub dns: Vec<String>,
    pub ip: Vec<IpAddr>,
    pub ca_url: String,
    pub key_name: Option<String>,
}

#[derive(Debug)]
pub struct DeleteKeyArgs {
    pub output_dir: PathBuf,
    pub confirm_key_name: String,
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
