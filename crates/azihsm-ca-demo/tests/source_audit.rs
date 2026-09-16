//! Static safety and dependency-boundary audit.

#![cfg(windows)]

use std::fs;
use std::path::Path;

#[test]
fn demo_has_no_private_export_overwrite_or_software_signer_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        fs::read_to_string(root.join("Cargo.toml")).unwrap_or_else(|error| panic!("{error}"));
    for exact in [
        "azihsm-ca-client = { path = \"../azihsm-ca-client\" }",
        "tracing = { version = \"=0.1.44\", default-features = false, features = [\"std\"] }",
        "tracing-subscriber = { version = \"=0.3.23\", default-features = false, features = [\"fmt\", \"std\"] }",
    ] {
        assert!(manifest.contains(exact), "missing {exact}");
    }
    for prohibited in ["openssl", "native-tls", "rustls", "aws-lc", "reqwest"] {
        assert!(!manifest.contains(prohibited), "found {prohibited}");
    }
    let mut source = String::new();
    collect(&root.join("src"), &mut source);
    let shared = root
        .parent()
        .unwrap_or_else(|| panic!("crate has no workspace parent"))
        .join("azihsm-ncrypt");
    collect(&shared.join("src"), &mut source);
    let client = root
        .parent()
        .unwrap_or_else(|| panic!("crate has no workspace parent"))
        .join("azihsm-ca-client");
    let client_manifest =
        fs::read_to_string(client.join("Cargo.toml")).unwrap_or_else(|error| panic!("{error}"));
    assert!(client_manifest.contains("ureq = { version = \"=3.4.2\", default-features = false }"));
    collect(&client.join("src"), &mut source);
    let mut naming_source = source.clone();
    let ca = root
        .parent()
        .unwrap_or_else(|| panic!("crate has no workspace parent"))
        .join("azihsm-ca");
    collect(&ca.join("src"), &mut naming_source);
    collect(&ca.join("tests"), &mut naming_source);
    for stale in [
        concat!("Azi", "Provider"),
        concat!("Azi", "Key"),
        concat!("Azi", "HsmSigningKey"),
    ] {
        assert!(
            !naming_source.contains(stale),
            "stale AziHSM identifier {stale}"
        );
    }
    for prohibited in [
        "NCRYPT_OVERWRITE_KEY_FLAG",
        "NCRYPT_MACHINE_KEY_FLAG",
        "NCRYPT_ALLOW_EXPORT_FLAG",
        "NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG",
        "-----BEGIN PRIVATE KEY-----",
        "rcgen::KeyPair",
        "generate_simple_self_signed",
        "EcdsaKeyPair",
        "RsaKeyPair",
    ] {
        assert!(!source.contains(prohibited), "found {prohibited}");
    }
    for required in [
        "NCryptCreatePersistedKey(",
        "NCryptFinalizeKey(",
        "NCryptOpenKey(",
        "NCryptSignHash(",
        "NCryptDeleteKey(",
        "BCRYPT_ECCPUBLIC_BLOB",
    ] {
        assert!(source.contains(required), "missing {required}");
    }
    assert_eq!(source.matches("NCryptSignHash(").count(), 1);
    for event in [
        "command_started",
        "provider_open_started",
        "provider_open_completed",
        "key_creation_started",
        "key_finalized",
        "key_recovery_started",
        "key_open_started",
        "key_open_completed",
        "public_key_export_started",
        "public_key_export_completed",
        "csr_generation_started",
        "csr_generation_completed",
        "readiness_check_started",
        "readiness_check_completed",
        "enrollment_started",
        "enrollment_completed",
        "certificate_verification_started",
        "certificate_verification_completed",
        "artifact_published",
        "staging_cleanup_completed",
        "key_deletion_started",
        "key_deletion_completed",
        "command_completed",
        "command_failed",
        "ncrypt_operation_failed",
    ] {
        assert!(source.contains(event), "missing logging event {event}");
    }
}

fn collect(path: &Path, output: &mut String) {
    for entry in fs::read_dir(path).unwrap_or_else(|error| panic!("{error}")) {
        let path = entry.unwrap_or_else(|error| panic!("{error}")).path();
        if path.is_dir() {
            collect(&path, output);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            output.push_str(&fs::read_to_string(path).unwrap_or_else(|error| panic!("{error}")));
        }
    }
}
