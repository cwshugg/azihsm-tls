//! Canonical identifier and persistent JSON encoding helpers.

use crate::error::{Error, ErrorClass, Result};
use serde::Serialize;

pub fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn canonical_json<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| {
        Error::new(
            ErrorClass::State,
            format!("{label} encoding failed: {error}"),
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_json_use_one_canonical_encoding() {
        assert!(is_lower_hex_32("0123456789abcdef0123456789abcdef"));
        assert!(!is_lower_hex_32("0123456789ABCDEF0123456789abcdef"));
        assert_eq!(
            canonical_json(&serde_json::json!({"a":1}), "test")
                .unwrap_or_else(|error| panic!("{error}")),
            b"{\"a\":1}\n"
        );
    }
}
