//! Versioned, deny-unknown-fields artifact metadata.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const REQUEST_METADATA: &str = "request-metadata.json";
pub const STAGING_METADATA: &str = "key-staging.json";
pub const FINALIZE_STARTED: &str = "finalize-started.json";
pub const FINALIZE_FAILED: &str = "finalize-failed.json";
pub const PUBLIC_DER: &str = "public-key.der";
pub const PUBLIC_PEM: &str = "public-key.pem";
pub const CSR_DER: &str = "request.csr.der";
pub const CSR_PEM: &str = "request.csr.pem";
pub const ROOT_DER: &str = "root.der";
pub const ROOT_PEM: &str = "root.pem";
pub const LEAF_DER: &str = "leaf.der";
pub const LEAF_PEM: &str = "leaf.pem";
pub const CHAIN_PEM: &str = "chain.pem";
pub const ISSUANCE_METADATA: &str = "issuance-metadata.json";
pub const DELETION_INTENT: &str = "deletion-intent.json";
pub const DELETION_RECORD: &str = "deletion-record.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StagingRecord {
    pub schema_version: u32,
    pub provider: String,
    pub key_name: String,
    pub algorithm: String,
    pub scope: String,
    pub subject_cn: String,
    pub dns_sans: Vec<String>,
    pub ip_sans: Vec<String>,
    pub ca_url: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestMetadata {
    pub schema_version: u32,
    pub provider: String,
    pub key_name: String,
    pub algorithm: String,
    pub scope: String,
    pub subject_cn: String,
    pub dns_sans: Vec<String>,
    pub ip_sans: Vec<String>,
    pub ca_url: String,
    pub idempotency_key: String,
    pub spki_sha256: String,
    pub csr_sha256: String,
    pub public_key_der: String,
    pub csr_der: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuanceMetadata {
    pub schema_version: u32,
    pub authority_id: String,
    pub issuance_id: String,
    pub http_status: u16,
    pub root_sha256: String,
    pub leaf_sha256: String,
    pub verified_at: String,
    pub root_der: String,
    pub leaf_der: String,
    pub chain_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeletionRecord {
    pub schema_version: u32,
    pub provider: String,
    pub key_name: String,
    pub spki_sha256: String,
    pub operation_id: String,
    pub requested_at: String,
    pub deleted_at: String,
    pub verified_absent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeletionIntent {
    pub schema_version: u32,
    pub provider: String,
    pub key_name: String,
    pub spki_sha256: String,
    pub confirmation_key_name: String,
    pub operation_id: String,
    pub requested_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaMetadata {
    pub schema_version: u32,
    pub authority_id: String,
    pub root: String,
    pub certificates: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyResponse {
    pub schema_version: u32,
    pub ready: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaError {
    pub schema_version: u32,
    pub error: CaErrorDetail,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaErrorDetail {
    pub code: String,
    pub message: String,
}
