//! Production-source and dependency safety audit.

use std::fs;
use std::path::Path;

#[test]
fn production_has_no_private_key_or_software_signer_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut source = String::new();
    for entry in fs::read_dir(root).unwrap_or_else(|error| panic!("{error}")) {
        let path = entry.unwrap_or_else(|error| panic!("{error}")).path();
        if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            source.push_str(&fs::read_to_string(path).unwrap_or_else(|error| panic!("{error}")));
        }
    }
    for forbidden in [
        "NCRYPT_ALLOW_EXPORT_FLAG",
        "NCRYPT_OVERWRITE_KEY_FLAG",
        "NCRYPT_MACHINE_KEY_FLAG",
        "Microsoft Software Key Storage Provider",
        "with_single_cert",
        "CertifiedKey::from_der",
        "any_supported_type",
        "rcgen::KeyPair",
        "ring::signature::EcdsaKeyPair",
    ] {
        assert!(!source.contains(forbidden), "forbidden source: {forbidden}");
    }
    assert!(source.contains("ECDSA_NISTP256_SHA256"));
    assert!(source.contains("try_acquire_owned"));
    assert!(source.contains("NoServerSessionStorage"));
}

#[test]
fn manifest_has_only_the_approved_runtime_stack() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .unwrap_or_else(|error| panic!("{error}"));
    for forbidden in [
        "azihsm-ca-demo",
        "openssl",
        "native-tls",
        "axum",
        "hyper",
        "async-trait",
        "fs2",
    ] {
        assert!(!manifest.contains(forbidden));
    }
    assert!(manifest.contains("tokio-rustls"));
    assert!(manifest.contains("default-features = false"));
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in fs::read_dir(source_root).unwrap_or_else(|error| panic!("{error}")) {
        let path = entry.unwrap_or_else(|error| panic!("{error}")).path();
        if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            let text = fs::read_to_string(path).unwrap_or_else(|error| panic!("{error}"));
            assert!(!text.contains("azihsm_ca_demo"));
        }
    }
}
