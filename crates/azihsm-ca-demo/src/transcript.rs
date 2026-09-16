//! Deterministic, default-on wire and local metadata transcript output.

use crate::{Error, ErrorClass, Result};
use azihsm_ncrypt::hash_sha256;
use serde::Serialize;

pub fn private_key_notice() {
    println!(
        "PRIVATE KEY LIMITATION: private key bytes and handles are never exported, available, or printed."
    );
}

pub fn http_request(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Body<'_>>,
) -> Result<()> {
    println!(
        "{}",
        render_exchange(
            "HTTP REQUEST",
            "outbound",
            method,
            path,
            None,
            headers,
            body
        )?
    );
    Ok(())
}

pub fn http_response(
    method: &str,
    path: &str,
    status: u16,
    headers: &[(&str, &str)],
    body: Body<'_>,
) -> Result<()> {
    println!(
        "{}",
        render_exchange(
            "HTTP RESPONSE",
            "inbound",
            method,
            path,
            Some(status),
            headers,
            Some(body),
        )?
    );
    Ok(())
}

pub fn local_json<T: Serialize>(direction: &str, name: &str, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|_| Error::new(ErrorClass::State, "cannot render local JSON transcript"))?;
    println!(
        "=== LOCAL JSON ===\nDirection: {direction}\nArtifact: {name}\nBody (JSON):\n{json}\n=== END LOCAL JSON ==="
    );
    Ok(())
}

#[derive(Clone, Copy)]
pub enum Body<'a> {
    Json(&'a [u8]),
    Pem { tag: &'a str, bytes: &'a [u8] },
}

fn render_exchange(
    title: &str,
    direction: &str,
    method: &str,
    path: &str,
    status: Option<u16>,
    headers: &[(&str, &str)],
    body: Option<Body<'_>>,
) -> Result<String> {
    let mut output =
        format!("=== {title} ===\nDirection: {direction}\nMethod: {method}\nPath: {path}\n");
    if let Some(status) = status {
        output.push_str(&format!("Status: {status}\n"));
    }
    for (name, value) in headers {
        output.push_str(&format!("{name}: {value}\n"));
    }
    if let Some(body) = body {
        match body {
            Body::Json(bytes) => {
                output.push_str(&format!(
                    "Byte-Length: {}\nSHA-256: {}\nBody (JSON):\n{}\n",
                    bytes.len(),
                    hex(&hash_sha256(bytes)?),
                    pretty_json(bytes)
                ));
            }
            Body::Pem { tag, bytes } => {
                output.push_str(&format!(
                    "Byte-Length: {}\nSHA-256: {}\nBody (PEM):\n{}",
                    bytes.len(),
                    hex(&hash_sha256(bytes)?),
                    pem::encode(&pem::Pem::new(tag, bytes))
                ));
            }
        }
    }
    output.push_str(&format!("=== END {title} ==="));
    Ok(output)
}

fn pretty_json(bytes: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_transcript_is_exact_and_pretty() {
        let output = render_exchange(
            "HTTP RESPONSE",
            "inbound",
            "GET",
            "/readyz",
            Some(200),
            &[("Content-Type", "application/json")],
            Some(Body::Json(br#"{"schema_version":1,"ready":true}"#)),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            output,
            "=== HTTP RESPONSE ===\nDirection: inbound\nMethod: GET\nPath: /readyz\nStatus: 200\nContent-Type: application/json\nByte-Length: 33\nSHA-256: 325b2bf4beb2df9a6c22a2fbb63c03b4d2645b308a4b03d43f213031b29957ce\nBody (JSON):\n{\n  \"ready\": true,\n  \"schema_version\": 1\n}\n=== END HTTP RESPONSE ==="
        );
    }

    #[test]
    fn csr_transcript_is_pem_and_contains_no_private_key() {
        let output = render_exchange(
            "HTTP REQUEST",
            "outbound",
            "POST",
            "/v1/certificates",
            None,
            &[
                ("Content-Type", "application/pkcs10"),
                ("Accept", "application/pkix-cert"),
                ("Idempotency-Key", "0123456789abcdef0123456789abcdef"),
            ],
            Some(Body::Pem {
                tag: "CERTIFICATE REQUEST",
                bytes: b"public-csr",
            }),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(output.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(output.contains("Byte-Length: 10"));
        assert!(output.contains("Idempotency-Key: 0123456789abcdef0123456789abcdef"));
        assert!(!output.contains("PRIVATE KEY-----"));
        assert!(!output.contains("key handle"));
    }

    #[test]
    fn certificate_transcript_is_pem() {
        let output = render_exchange(
            "HTTP RESPONSE",
            "inbound",
            "GET",
            "/v1/ca/root",
            Some(200),
            &[("Content-Type", "application/pkix-cert")],
            Some(Body::Pem {
                tag: "CERTIFICATE",
                bytes: b"public-certificate",
            }),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(output.contains("-----BEGIN CERTIFICATE-----"));
        assert!(output.contains("SHA-256:"));
    }

    #[test]
    fn metadata_and_error_json_are_pretty_and_complete() {
        for (path, status, body, required) in [
            (
                "/v1/ca",
                200,
                br#"{"schema_version":1,"authority_id":"0123456789abcdef0123456789abcdef","root":"/v1/ca/root","certificates":"/v1/certificates"}"#.as_slice(),
                "\"authority_id\": \"0123456789abcdef0123456789abcdef\"",
            ),
            (
                "/v1/certificates",
                422,
                br#"{"schema_version":1,"error":{"code":"unsupported_csr_profile","message":"request rejected"}}"#.as_slice(),
                "\"code\": \"unsupported_csr_profile\"",
            ),
        ] {
            let output = render_exchange(
                "HTTP RESPONSE",
                "inbound",
                if status == 200 { "GET" } else { "POST" },
                path,
                Some(status),
                &[("Content-Type", "application/json")],
                Some(Body::Json(body)),
            )
            .unwrap_or_else(|error| panic!("{error}"));
            assert!(output.contains(required));
            assert!(output.contains("\n  \""));
            assert!(output.contains(&format!("Status: {status}")));
        }
    }

    #[test]
    fn replay_transcript_includes_status_and_issuance_header() {
        let output = render_exchange(
            "HTTP RESPONSE",
            "inbound",
            "POST",
            "/v1/certificates",
            Some(200),
            &[
                ("Content-Type", "application/pkix-cert"),
                ("X-AziHSM-Issuance-Id", "0123456789abcdef0123456789abcdef"),
            ],
            Some(Body::Pem {
                tag: "CERTIFICATE",
                bytes: b"replayed-certificate",
            }),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(output.contains("Status: 200"));
        assert!(output.contains("X-AziHSM-Issuance-Id: 0123456789abcdef0123456789abcdef"));
        assert!(output.contains("-----BEGIN CERTIFICATE-----"));
    }
}
