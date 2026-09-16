//! Bounded plain-HTTP client for the exact demonstration CA API.

use crate::model::{CaError, CaMetadata, ReadyResponse};
use crate::transcript::{self, Body};
use crate::{Error, ErrorClass, Result};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use transcript::TranscriptSink;

const JSON_LIMIT: usize = 64 * 1024;
const CERT_LIMIT: usize = 256 * 1024;
const HEADER_LIMIT: usize = 16 * 1024;

#[derive(Debug)]
pub struct Enrollment {
    pub status: u16,
    pub issuance_id: String,
    pub leaf_der: Vec<u8>,
}

/// CA operation associated with a typed boundary failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaOperation {
    Readiness,
    Metadata,
    Root,
    Enrollment,
}

/// Stable startup-policy classification for CA failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaFailureKind {
    Availability,
    Protocol,
}

/// A classified CA failure preserving the bounded public error.
#[derive(Debug)]
pub struct CaFailure {
    pub kind: CaFailureKind,
    pub operation: CaOperation,
    pub source: Error,
}

pub struct CaClient {
    base: String,
    agent: ureq::Agent,
    transcript: Arc<dyn TranscriptSink>,
}

impl CaClient {
    pub fn new(base: &str) -> Self {
        Self::with_sink(base, transcript::default_sink())
    }

    pub fn with_sink(base: &str, transcript: Arc<dyn TranscriptSink>) -> Self {
        Self::with_timeouts(
            base,
            Duration::from_secs(3),
            Duration::from_secs(10),
            transcript,
        )
    }

    fn with_timeouts(
        base: &str,
        connect: Duration,
        global: Duration,
        transcript: Arc<dyn TranscriptSink>,
    ) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(HEADER_LIMIT)
            .timeout_connect(Some(connect))
            .timeout_global(Some(global))
            .build()
            .into();
        Self {
            base: base.to_owned(),
            agent,
            transcript,
        }
    }

    pub fn ready(&self) -> Result<()> {
        self.ready_typed().map_err(|failure| failure.source)
    }

    pub fn ready_typed(&self) -> std::result::Result<(), CaFailure> {
        let operation = CaOperation::Readiness;
        tracing::info!(
            event = "readiness_check_started",
            message = "Checking whether the CA is ready to issue certificates."
        );
        let (status, content_type, body) =
            self.get_typed(operation, "/readyz", "application/json", JSON_LIMIT)?;
        transcript::http_response_to(
            self.transcript.as_ref(),
            "GET",
            "/readyz",
            status,
            &[(
                "Content-Type",
                content_type.as_deref().unwrap_or("<missing>"),
            )],
            Body::Json(&body),
        )
        .map_err(|source| Self::protocol(operation, source))?;
        if status != 200 {
            return Err(Self::status_failure(operation, status, &body));
        }
        require_content_type(content_type.as_deref(), "application/json")
            .map_err(|source| Self::protocol(operation, source))?;
        let response: ReadyResponse =
            parse_json(&body).map_err(|source| Self::protocol(operation, source))?;
        if response.schema_version != 1 || !response.ready {
            tracing::warn!(
                event = "readiness_check_not_ready",
                message = "The CA is not ready, so certificate issuance cannot safely continue."
            );
            return Err(CaFailure {
                kind: if response.schema_version == 1 {
                    CaFailureKind::Availability
                } else {
                    CaFailureKind::Protocol
                },
                operation,
                source: http("CA readiness response was not ready"),
            });
        }
        tracing::info!(
            event = "readiness_check_completed",
            message = "The CA reports that it is ready to issue certificates."
        );
        Ok(())
    }

    pub fn metadata(&self) -> Result<CaMetadata> {
        self.metadata_typed().map_err(|failure| failure.source)
    }

    pub fn metadata_typed(&self) -> std::result::Result<CaMetadata, CaFailure> {
        let operation = CaOperation::Metadata;
        tracing::info!(
            event = "ca_metadata_fetch_started",
            message = "Reading the CA authority identity and supported certificate endpoints."
        );
        let (status, content_type, body) =
            self.get_typed(operation, "/v1/ca", "application/json", JSON_LIMIT)?;
        transcript::http_response_to(
            self.transcript.as_ref(),
            "GET",
            "/v1/ca",
            status,
            &[(
                "Content-Type",
                content_type.as_deref().unwrap_or("<missing>"),
            )],
            Body::Json(&body),
        )
        .map_err(|source| Self::protocol(operation, source))?;
        if status != 200 {
            return Err(Self::status_failure(operation, status, &body));
        }
        require_content_type(content_type.as_deref(), "application/json")
            .map_err(|source| Self::protocol(operation, source))?;
        let metadata: CaMetadata =
            parse_json(&body).map_err(|source| Self::protocol(operation, source))?;
        if metadata.schema_version != 1
            || metadata.root != "/v1/ca/root"
            || metadata.certificates != "/v1/certificates"
            || !is_lower_hex_32(&metadata.authority_id)
        {
            return Err(Self::protocol(
                operation,
                http("CA metadata does not match the supported schema"),
            ));
        }
        tracing::info!(
            event = "ca_metadata_fetch_completed",
            authority_id = metadata.authority_id,
            message = "The CA authority identity and endpoints match the supported protocol."
        );
        Ok(metadata)
    }

    pub fn root(&self) -> Result<Vec<u8>> {
        self.root_typed().map_err(|failure| failure.source)
    }

    pub fn root_typed(&self) -> std::result::Result<Vec<u8>, CaFailure> {
        let operation = CaOperation::Root;
        tracing::info!(
            event = "root_fetch_started",
            message =
                "Fetching the public CA root for local verification and client trust provisioning."
        );
        let (status, content_type, body) = self.get_typed(
            operation,
            "/v1/ca/root",
            "application/pkix-cert",
            CERT_LIMIT,
        )?;
        transcript::http_response_to(
            self.transcript.as_ref(),
            "GET",
            "/v1/ca/root",
            status,
            &[(
                "Content-Type",
                content_type.as_deref().unwrap_or("<missing>"),
            )],
            if status == 200 {
                Body::Pem {
                    tag: "CERTIFICATE",
                    bytes: &body,
                }
            } else {
                Body::Json(&body)
            },
        )
        .map_err(|source| Self::protocol(operation, source))?;
        if status != 200 {
            return Err(Self::status_failure(operation, status, &body));
        }
        require_content_type(content_type.as_deref(), "application/pkix-cert")
            .map_err(|source| Self::protocol(operation, source))?;
        tracing::info!(
            event = "root_fetch_completed",
            message =
                "The public CA root was fetched for verification and independent client trust."
        );
        Ok(body)
    }

    pub fn enroll(
        &self,
        csr: &[u8],
        idempotency_key: &str,
        dns_sans: &[String],
        ip_sans: &[IpAddr],
        recovery_guidance: &str,
    ) -> Result<Enrollment> {
        self.enroll_typed(csr, idempotency_key, dns_sans, ip_sans, recovery_guidance)
            .map_err(|failure| failure.source)
    }

    pub fn enroll_typed(
        &self,
        csr: &[u8],
        idempotency_key: &str,
        dns_sans: &[String],
        ip_sans: &[IpAddr],
        recovery_guidance: &str,
    ) -> std::result::Result<Enrollment, CaFailure> {
        let operation = CaOperation::Enrollment;
        tracing::info!(
            event = "enrollment_started",
            message = "Submitting the public CSR, which proves key possession without sending the private key; the idempotency key makes retries replay-safe."
        );
        let url = self.url("/v1/certificates");
        transcript::http_request_to(
            self.transcript.as_ref(),
            "POST",
            "/v1/certificates",
            &[
                ("Content-Type", "application/pkcs10"),
                ("Accept", "application/pkix-cert"),
                ("Idempotency-Key", idempotency_key),
            ],
            Some(Body::Pem {
                tag: "CERTIFICATE REQUEST",
                bytes: csr,
            }),
        )
        .map_err(|source| Self::protocol(operation, source))?;
        let mut response = self
            .agent
            .post(&url)
            .header("Content-Type", "application/pkcs10")
            .header("Accept", "application/pkix-cert")
            .header("Idempotency-Key", idempotency_key)
            .send(csr)
            .map_err(|error| {
                Self::transport_failure(operation, error, "CA enrollment request failed")
            })?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("Content-Type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let issuance_id = response
            .headers()
            .get("X-AziHSM-Issuance-Id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = response
            .body_mut()
            .with_config()
            .limit(CERT_LIMIT as u64)
            .read_to_vec()
            .map_err(|error| {
                Self::transport_failure(
                    operation,
                    error,
                    "CA enrollment response exceeded limits or could not be read",
                )
            })?;
        transcript::http_response_to(
            self.transcript.as_ref(),
            "POST",
            "/v1/certificates",
            status,
            &[
                (
                    "Content-Type",
                    content_type.as_deref().unwrap_or("<missing>"),
                ),
                (
                    "X-AziHSM-Issuance-Id",
                    if issuance_id.is_empty() {
                        "<missing>"
                    } else {
                        &issuance_id
                    },
                ),
            ],
            if matches!(status, 200 | 201) {
                Body::Pem {
                    tag: "CERTIFICATE",
                    bytes: &body,
                }
            } else {
                Body::Json(&body)
            },
        )
        .map_err(|source| Self::protocol(operation, source))?;
        if !matches!(status, 200 | 201) {
            let mut failure = Self::status_failure(operation, status, &body);
            if status < 500 {
                failure.source =
                    parse_enrollment_error(status, &body, dns_sans, ip_sans, recovery_guidance);
            }
            return Err(failure);
        }
        require_content_type(content_type.as_deref(), "application/pkix-cert")
            .map_err(|source| Self::protocol(operation, source))?;
        if !is_lower_hex_32(&issuance_id) {
            return Err(Self::protocol(
                operation,
                http("CA enrollment response omitted a valid issuance ID"),
            ));
        }
        let message = if status == 201 {
            "The CA issued a new certificate for this CSR."
        } else {
            "The CA returned the byte-identical certificate from an idempotent retry."
        };
        tracing::info!(event = "enrollment_completed", issuance_id, status, message);
        Ok(Enrollment {
            status,
            issuance_id,
            leaf_der: body,
        })
    }

    fn get_typed(
        &self,
        operation: CaOperation,
        path: &str,
        accept: &str,
        limit: usize,
    ) -> std::result::Result<(u16, Option<String>, Vec<u8>), CaFailure> {
        transcript::http_request_to(
            self.transcript.as_ref(),
            "GET",
            path,
            &[("Accept", accept)],
            None,
        )
        .map_err(|source| Self::protocol(operation, source))?;
        let mut response = self
            .agent
            .get(self.url(path))
            .header("Accept", accept)
            .call()
            .map_err(|error| Self::transport_failure(operation, error, "CA request failed"))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("Content-Type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response
            .body_mut()
            .with_config()
            .limit(limit as u64)
            .read_to_vec()
            .map_err(|error| {
                Self::transport_failure(
                    operation,
                    error,
                    "CA response exceeded limits or could not be read",
                )
            })?;
        Ok((status, content_type, body))
    }

    fn status_failure(operation: CaOperation, status: u16, body: &[u8]) -> CaFailure {
        tracing::warn!(
            event = "ca_request_failed",
            status,
            message = "The CA returned an unsuccessful status; the exact bounded response remains in the transcript."
        );
        CaFailure {
            kind: if (500..=599).contains(&status) {
                CaFailureKind::Availability
            } else {
                CaFailureKind::Protocol
            },
            operation,
            source: parse_ca_error(status, body),
        }
    }

    fn protocol(operation: CaOperation, source: Error) -> CaFailure {
        tracing::warn!(
            event = "ca_protocol_failed",
            message = "The CA response did not match the bounded protocol contract, so the client fails closed."
        );
        CaFailure {
            kind: CaFailureKind::Protocol,
            operation,
            source,
        }
    }

    fn transport_failure(
        operation: CaOperation,
        error: ureq::Error,
        message: &'static str,
    ) -> CaFailure {
        let kind = match error {
            ureq::Error::Io(_)
            | ureq::Error::Timeout(_)
            | ureq::Error::HostNotFound
            | ureq::Error::ConnectionFailed => CaFailureKind::Availability,
            ureq::Error::StatusCode(_)
            | ureq::Error::Http(_)
            | ureq::Error::BadUri(_)
            | ureq::Error::Protocol(_)
            | ureq::Error::RedirectFailed
            | ureq::Error::InvalidProxyUrl
            | ureq::Error::BodyExceedsLimit(_)
            | ureq::Error::TooManyRedirects
            | ureq::Error::Tls(_)
            | ureq::Error::RequireHttpsOnly(_)
            | ureq::Error::LargeResponseHeader(_, _)
            | ureq::Error::ConnectProxyFailed(_)
            | ureq::Error::TlsRequired
            | ureq::Error::Other(_)
            | ureq::Error::BodyStalled => CaFailureKind::Protocol,
            _ => CaFailureKind::Protocol,
        };
        tracing::warn!(
            event = "ca_transport_failed",
            kind = ?kind,
            message = "The CA exchange failed before a valid response was accepted; availability failures may use an already verified cache, while protocol failures fail closed."
        );
        CaFailure {
            kind,
            operation,
            source: http(message),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| http("CA returned malformed JSON"))
}

fn require_content_type(actual: Option<&str>, expected: &str) -> Result<()> {
    if actual.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
    }) {
        Ok(())
    } else {
        Err(http("CA returned an unexpected Content-Type"))
    }
}

fn parse_ca_error(status: u16, body: &[u8]) -> Error {
    match serde_json::from_slice::<CaError>(body) {
        Ok(error) if error.schema_version == 1 && !error.error.code.is_empty() => Error::new(
            ErrorClass::Http,
            format!(
                "CA request failed with HTTP {status}: {}: {}",
                error.error.code, error.error.message
            ),
        ),
        _ => http(format!(
            "CA request failed with HTTP {status} and an invalid error body"
        )),
    }
}

fn parse_enrollment_error(
    status: u16,
    body: &[u8],
    dns_sans: &[String],
    ip_sans: &[IpAddr],
    recovery_guidance: &str,
) -> Error {
    let Ok(error) = serde_json::from_slice::<CaError>(body) else {
        return parse_ca_error(status, body);
    };
    if error.schema_version != 1
        || error.error.code.is_empty()
        || error.error.code != "san_not_authorized"
    {
        return parse_ca_error(status, body);
    }

    let mut message = format!(
        "CA request failed with HTTP {status}: {}: {}\n\n\
         SAN authorization guidance:\n\
         CA --listen controls only network binding; it does not authorize certificate names.\n\
         Every requested DNS/IP SAN must exactly match a CA --allow-dns/--allow-ip value; \
         wildcards are not supported.",
        error.error.code, error.error.message
    );
    if !dns_sans.is_empty() {
        message.push_str("\nRequested DNS SANs (--allow-dns):");
        for dns in dns_sans {
            message.push_str(&format!("\n  - {dns:?}"));
        }
    }
    if !ip_sans.is_empty() {
        message.push_str("\nRequested IP SANs (--allow-ip):");
        for ip in ip_sans {
            message.push_str(&format!("\n  - \"{ip}\""));
        }
    }
    if !recovery_guidance.is_empty() {
        message.push('\n');
        message.push_str(recovery_guidance);
    }
    Error::new(ErrorClass::Http, message)
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn http(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::Http, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const RECOVERY_GUIDANCE: &str = "After restarting or reconfiguring the CA, rerun the client.";

    #[test]
    fn nested_error_schema_is_required() {
        let error = parse_ca_error(
            422,
            br#"{"schema_version":1,"error":{"code":"unsupported_csr_profile","message":"request rejected"}}"#,
        );
        assert!(error.to_string().contains("unsupported_csr_profile"));
        assert!(
            parse_ca_error(500, br#"{"error":"flat"}"#)
                .to_string()
                .contains("invalid error body")
        );
    }

    #[test]
    fn typed_failure_classification_is_fail_closed() {
        for error in [
            ureq::Error::Io(std::io::Error::other("socket")),
            ureq::Error::HostNotFound,
            ureq::Error::ConnectionFailed,
        ] {
            assert_eq!(
                CaClient::transport_failure(CaOperation::Readiness, error, "test").kind,
                CaFailureKind::Availability
            );
        }
        for error in [
            ureq::Error::RedirectFailed,
            ureq::Error::TooManyRedirects,
            ureq::Error::BodyExceedsLimit(1),
            ureq::Error::LargeResponseHeader(1, 2),
            ureq::Error::Other(Box::new(std::io::Error::other("unknown"))),
        ] {
            assert_eq!(
                CaClient::transport_failure(CaOperation::Readiness, error, "test").kind,
                CaFailureKind::Protocol
            );
        }
        assert_eq!(
            CaClient::status_failure(CaOperation::Metadata, 503, b"{}").kind,
            CaFailureKind::Availability
        );
        for status in [199, 301, 400, 499, 600] {
            assert_eq!(
                CaClient::status_failure(CaOperation::Metadata, status, b"{}").kind,
                CaFailureKind::Protocol
            );
        }
    }

    #[test]
    fn enrollment_accepts_201_and_200_with_exact_headers() {
        for status in [201, 200] {
            let (base, server) = one_response(
                status,
                &[
                    ("Content-Type", "application/pkix-cert"),
                    ("X-AziHSM-Issuance-Id", "0123456789abcdef0123456789abcdef"),
                ],
                b"certificate",
                Duration::ZERO,
            );
            let enrollment = CaClient::new(&base)
                .enroll(
                    b"csr",
                    "fedcba9876543210fedcba9876543210",
                    &[],
                    &[],
                    RECOVERY_GUIDANCE,
                )
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(enrollment.status, status);
            assert_eq!(enrollment.leaf_der, b"certificate");
            let request = server.join().unwrap_or_else(|_| panic!("server failed"));
            assert!(request.starts_with("post /v1/certificates http/1.1\r\n"));
            assert!(request.contains("content-type: application/pkcs10\r\n"));
            assert!(request.contains("accept: application/pkix-cert\r\n"));
            assert!(request.contains("idempotency-key: fedcba9876543210fedcba9876543210\r\n"));
        }
    }

    #[test]
    fn rejects_redirect_oversize_and_timeout() {
        let (base, server) = one_response(
            302,
            &[("Location", "http://127.0.0.1:1/elsewhere")],
            b"",
            Duration::ZERO,
        );
        assert!(CaClient::new(&base).ready().is_err());
        let _ = server.join();

        let body = vec![b'x'; JSON_LIMIT + 1];
        let (base, server) = one_response(
            200,
            &[("Content-Type", "application/json")],
            &body,
            Duration::ZERO,
        );
        assert!(CaClient::new(&base).ready().is_err());
        let _ = server.join();

        let (base, server) = one_response(
            200,
            &[("Content-Type", "application/json")],
            br#"{"schema_version":1,"ready":true}"#,
            Duration::from_millis(100),
        );
        assert!(
            CaClient::with_timeouts(
                &base,
                Duration::from_millis(20),
                Duration::from_millis(20),
                transcript::default_sink(),
            )
            .ready()
            .is_err()
        );
        let _ = server.join();
    }

    #[test]
    fn enrollment_parses_exact_nested_ca_error() {
        let body = br#"{"schema_version":1,"error":{"code":"unsupported_csr_profile","message":"request rejected"}}"#;
        let (base, server) = one_response(
            422,
            &[("Content-Type", "application/json")],
            body,
            Duration::ZERO,
        );
        let error = CaClient::new(&base)
            .enroll(
                b"csr",
                "fedcba9876543210fedcba9876543210",
                &[],
                &[],
                RECOVERY_GUIDANCE,
            )
            .expect_err("error response must fail");
        assert_eq!(
            error.to_string(),
            "Http: CA request failed with HTTP 422: unsupported_csr_profile: request rejected"
        );
        let _ = server.join();
    }

    #[test]
    fn enrollment_explains_exact_san_authorization_and_retry() {
        let body = br#"{"schema_version":1,"error":{"code":"san_not_authorized","message":"one or more requested SANs are not authorized"}}"#;
        let (base, server) = one_response(
            403,
            &[("Content-Type", "application/json")],
            body,
            Duration::ZERO,
        );
        let error = CaClient::new(&base)
            .enroll(
                b"csr",
                "fedcba9876543210fedcba9876543210",
                &["server.demo".to_owned()],
                &["192.0.2.20"
                    .parse()
                    .unwrap_or_else(|parse_error| panic!("{parse_error}"))],
                RECOVERY_GUIDANCE,
            )
            .expect_err("unauthorized SAN response must fail");
        assert_eq!(
            error.to_string(),
            concat!(
                "Http: CA request failed with HTTP 403: san_not_authorized: ",
                "one or more requested SANs are not authorized\n\n",
                "SAN authorization guidance:\n",
                "CA --listen controls only network binding; it does not authorize certificate ",
                "names.\n",
                "Every requested DNS/IP SAN must exactly match a CA --allow-dns/--allow-ip ",
                "value; wildcards are not supported.\n",
                "Requested DNS SANs (--allow-dns):\n",
                "  - \"server.demo\"\n",
                "Requested IP SANs (--allow-ip):\n",
                "  - \"192.0.2.20\"\n",
                "After restarting or reconfiguring the CA, rerun the client."
            )
        );
        let _ = server.join();
    }

    fn one_response(
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
        delay: Duration,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let headers = headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        let body = body.to_vec();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap_or_else(|error| panic!("{error}"));
            let mut request = Vec::new();
            let mut chunk = [0_u8; 2048];
            loop {
                let count = stream
                    .read(&mut chunk)
                    .unwrap_or_else(|error| panic!("{error}"));
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
                let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                let content_length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            thread::sleep(delay);
            let reason = match status {
                200 => "OK",
                201 => "Created",
                302 => "Found",
                _ => "Error",
            };
            let mut response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n",
                body.len()
            );
            for (name, value) in headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str("Connection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
            String::from_utf8_lossy(&request).to_ascii_lowercase()
        });
        (format!("http://{address}"), handle)
    }
}
