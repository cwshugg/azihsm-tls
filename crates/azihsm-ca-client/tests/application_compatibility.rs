//! Cross-application dependency and protocol compatibility checks.

use azihsm_ca_client::{CaMetadata, ReadyResponse};
use std::fs;
use std::path::Path;

#[test]
fn applications_depend_on_client_but_not_each_other() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| panic!("client crate has no workspace parent"));
    let demo = fs::read_to_string(workspace.join("azihsm-ca-demo").join("Cargo.toml"))
        .unwrap_or_else(|error| panic!("{error}"));
    let server = fs::read_to_string(workspace.join("azihsm-tls-server").join("Cargo.toml"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(demo.contains("azihsm-ca-client"));
    assert!(server.contains("azihsm-ca-client"));
    assert!(!demo.contains("azihsm-tls-server"));
    assert!(!server.contains("azihsm-ca-demo"));

    let demo_source = collect_source(&workspace.join("azihsm-ca-demo").join("src"));
    let server_source = collect_source(&workspace.join("azihsm-tls-server").join("src"));
    let client_source = collect_source(&workspace.join("azihsm-ca-client").join("src"));
    assert!(demo_source.contains("state_lock::StateLock"));
    assert!(server_source.contains("state_lock::StateLock"));
    assert!(!demo_source.contains("LockFileEx"));
    assert!(!server_source.contains("LockFileEx"));
    assert_eq!(client_source.matches("LockFileEx(").count(), 1);
}

#[test]
fn exact_ca_response_dtos_are_shared() {
    let ready: ReadyResponse = serde_json::from_str(r#"{"schema_version":1,"ready":true}"#)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(ready.schema_version, 1);
    assert!(ready.ready);

    let metadata: CaMetadata = serde_json::from_str(
        r#"{"schema_version":1,"authority_id":"0123456789abcdef0123456789abcdef","root":"/v1/ca/root","certificates":"/v1/certificates"}"#,
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(metadata.root, "/v1/ca/root");
    assert_eq!(metadata.certificates, "/v1/certificates");
}

#[test]
fn human_narration_coexists_with_stable_events_and_safe_wording() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| panic!("client crate has no workspace parent"));
    let shared = collect_source(&workspace.join("azihsm-ca-client").join("src"));
    let demo = collect_source(&workspace.join("azihsm-ca-demo").join("src"));
    let server = collect_source(&workspace.join("azihsm-tls-server").join("src"));
    for (event, phrase) in [
        ("readiness_check_started", "ready to issue certificates"),
        ("ca_metadata_fetch_started", "authority identity"),
        ("root_fetch_started", "public CA root"),
        ("enrollment_started", "without sending the private key"),
        ("enrollment_completed", "idempotent retry"),
        ("enrollment_completed", "issued a new certificate"),
        (
            "certificate_verification_started",
            "signatures, profile, validity, SANs",
        ),
        (
            "certificate_verification_completed",
            "belongs to the requested AziHSM key",
        ),
        ("ca_request_failed", "exact bounded response"),
    ] {
        assert!(shared.contains(event), "missing shared event {event}");
        assert!(shared.contains(phrase), "missing shared narration {phrase}");
    }
    for phrase in [
        "Creating one named AziHSM key",
        "Retrying enrollment with the existing key",
        "Showing public certificate metadata",
        "irreversibly deleting the exact named AziHSM key",
    ] {
        assert!(
            shared.contains(phrase) || demo.contains(phrase),
            "missing demo narration {phrase}"
        );
    }
    for phrase in [
        "bind address controls network reachability",
        "all 64 bounded connection permits",
        "server does not authenticate the client",
        "four-byte-length-prefixed frame",
        "TLS close_notify",
        "selected certificate expired",
    ] {
        assert!(server.contains(phrase), "missing server narration {phrase}");
    }
    let all = format!("{shared}{demo}{server}");
    assert!(!all.contains(concat!("server authenticated", " the client")));
    assert!(!all.contains(concat!("private key bytes", " were exported")));
    assert!(!all.contains(concat!("private key handle", " was printed")));
}

fn collect_source(directory: &Path) -> String {
    fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{error}"))
        .map(|entry| entry.unwrap_or_else(|error| panic!("{error}")).path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("rs"))
        .map(|path| fs::read_to_string(path).unwrap_or_else(|error| panic!("{error}")))
        .collect::<Vec<_>>()
        .join("")
}
