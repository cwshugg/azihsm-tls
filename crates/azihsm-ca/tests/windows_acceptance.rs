//! Standalone Windows acceptance harness entry point.

#![cfg(windows)]

use azihsm_ca::state::hex;
use azihsm_ca::win::bcrypt::hash_sha256;
use azihsm_ca::win::crypt32::{CertContext, verify_certificate_signature, verify_exclusive_chain};
use std::env;
use std::fs;
use std::path::PathBuf;

#[test]
#[ignore = "requires transferred cross-VM enrollment artifacts"]
fn validate_cross_vm_enrollment_artifacts() {
    let root_path = required_absolute("AZIHSM_ACCEPTANCE_ROOT_DER");
    let _csr_path = required_absolute("AZIHSM_ACCEPTANCE_CSR_DER");
    let certificate_path = required_absolute("AZIHSM_ACCEPTANCE_CERT_DER");
    let expected_root_hash = required("AZIHSM_ACCEPTANCE_ROOT_SHA256");
    let expected_spki_hash = required("AZIHSM_ACCEPTANCE_ROOT_SPKI_SHA256");
    let _dns = required("AZIHSM_ACCEPTANCE_DNS");
    let _ip = required("AZIHSM_ACCEPTANCE_IP");
    let root = fs::read(root_path).unwrap_or_else(|error| panic!("BLOCKED: root read: {error}"));
    let certificate = fs::read(certificate_path)
        .unwrap_or_else(|error| panic!("BLOCKED: certificate read: {error}"));
    assert_eq!(
        hex(&hash_sha256(&root).unwrap_or_else(|error| panic!("{error}"))),
        expected_root_hash
    );
    let root_context = CertContext::create(&root).unwrap_or_else(|error| panic!("FAIL: {error}"));
    let leaf_context =
        CertContext::create(&certificate).unwrap_or_else(|error| panic!("FAIL: {error}"));
    verify_certificate_signature(&root, &root_context)
        .unwrap_or_else(|error| panic!("FAIL: root signature: {error}"));
    verify_certificate_signature(&certificate, &root_context)
        .unwrap_or_else(|error| panic!("FAIL: leaf signature: {error}"));
    verify_exclusive_chain(&root_context, &leaf_context, &root, &certificate)
        .unwrap_or_else(|error| panic!("FAIL: chain: {error}"));
    let spki = unsafe {
        let info = &*root_context.public_key_info();
        let point =
            std::slice::from_raw_parts(info.PublicKey.pbData, info.PublicKey.cbData as usize);
        azihsm_ca::win::crypt32::spki_der_from_blob(&{
            let mut blob = [0u8; 72];
            blob[..4].copy_from_slice(&0x3153_4345u32.to_le_bytes());
            blob[4..8].copy_from_slice(&32u32.to_le_bytes());
            blob[8..].copy_from_slice(&point[1..]);
            blob
        })
    };
    assert_eq!(
        hex(&hash_sha256(&spki).unwrap_or_else(|error| panic!("{error}"))),
        expected_spki_hash
    );
    println!("PASS: root hash, root SPKI, signatures, and exclusive two-element chain");
}

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("BLOCKED: missing {name}"))
}

fn required_absolute(name: &str) -> PathBuf {
    let path = PathBuf::from(required(name));
    assert!(path.is_absolute(), "BLOCKED: {name} must be absolute");
    path
}
