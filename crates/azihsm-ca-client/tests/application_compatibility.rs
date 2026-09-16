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

fn collect_source(directory: &Path) -> String {
    fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{error}"))
        .map(|entry| entry.unwrap_or_else(|error| panic!("{error}")).path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("rs"))
        .map(|path| fs::read_to_string(path).unwrap_or_else(|error| panic!("{error}")))
        .collect::<Vec<_>>()
        .join("")
}
