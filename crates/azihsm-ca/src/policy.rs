//! Fixed provider, profile, transport, and warning policy.

pub const PROVIDER_NAME: &str = "Microsoft Azure Integrated HSM Key Storage Provider";
pub const ROOT_CN: &str = "AziHSM Demo Root";
pub const CLOCK_SKEW_SECONDS: i64 = 300;
pub const MAX_ECC_BLOB: usize = 1024;
pub const MAX_SIGNATURE: usize = 256;
pub const SERVER_AUTH_OID: &[u8] = b"1.3.6.1.5.5.7.3.1\0";
pub const ACCEPTED_RISKS: [&str; 5] = [
    "Any reachable caller can obtain a certificate for an allowlisted SAN using its own key.",
    "Any process running as the CA account can reopen and use the named key, bypassing policy, records, limits, and audit.",
    "Coherent local rollback, replacement, or deletion may be undetectable; status and audit may be incomplete or inaccurate.",
    "Plain HTTP provides no confidentiality, integrity, or endpoint authentication; binding and firewall rules reduce reachability only.",
    "Revocation, CRLs, and OCSP are not provided; certificates can remain usable until expiry or trust removal.",
];

pub fn warning_text() -> String {
    let mut text = String::from("DEMONSTRATION CA - ACCEPTED RISKS:\n");
    for (index, risk) in ACCEPTED_RISKS.iter().enumerate() {
        text.push_str(&format!("  {}. {risk}\n", index + 1));
    }
    text
}
