//! Release-safety and dependency-policy source audit.

#![cfg(windows)]

use std::fs;
use std::path::Path;

#[test]
fn product_has_no_prohibited_dependencies_or_fault_controls() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        fs::read_to_string(root.join("Cargo.toml")).unwrap_or_else(|error| panic!("{error}"));
    for prohibited in [
        "openssl",
        "rustls",
        "aws-lc",
        "native-tls",
        "webpki",
        "async-std",
        "smol",
        "hyper",
        "reqwest",
        "[features]",
        "Win32_Globalization",
        "Win32_Networking_WinSock",
    ] {
        assert!(!manifest.contains(prohibited), "found {prohibited}");
    }
    let mut source = String::new();
    collect_rs(&root.join("src"), &mut source);
    for prohibited in [
        "NCRYPT_OVERWRITE_KEY_FLAG",
        "NCRYPT_MACHINE_KEY_FLAG",
        "FAULT_INJECT",
        "CRASH_AFTER",
        "FAIL_AFTER",
        "verify endpoint",
        "rcgen::KeyPair",
        "generate_simple_self_signed",
        "EcdsaKeyPair",
        "Ed25519KeyPair",
        "BCryptOpen",
        "BCryptCreate",
        "BCryptHash",
        "BCryptFinish",
        "BCryptDestroy",
        "BCryptClose",
        "BCryptGenRandom",
        "BCryptGenerateKeyPair",
        "BCryptImportKeyPair",
        "BCryptVerifySignature",
    ] {
        assert!(!source.contains(prohibited), "found {prohibited}");
    }
    assert!(!manifest.contains("futures-util ="));
    assert_eq!(
        source.matches("NCryptSignHash(").count(),
        1,
        "expected one production FFI seam"
    );
}

fn collect_rs(path: &Path, output: &mut String) {
    for entry in fs::read_dir(path).unwrap_or_else(|error| panic!("{error}")) {
        let path = entry.unwrap_or_else(|error| panic!("{error}")).path();
        if path.is_dir() {
            collect_rs(&path, output);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            output.push_str(&fs::read_to_string(path).unwrap_or_else(|error| panic!("{error}")));
        }
    }
}
