//! TLS server adapters for shared artifact operations.

use crate::Result;
use crate::ca_cli::{CreateArgs, DeleteKeyArgs};
use azihsm_ca_client::{artifacts, model::RequestMetadata};
use std::path::Path;

const RETRY_GUIDANCE: &str = "After restarting or reconfiguring the CA, rerun \
    azihsm-tls-server with the same state directory and identity arguments. The existing AziHSM \
    key, CSR, and idempotency key will be reused.";

pub fn create(args: CreateArgs) -> Result<()> {
    artifacts::create(artifacts::CreateArgs {
        output_dir: args.output_dir,
        subject_cn: args.subject_cn,
        dns: args.dns,
        ip: args.ip,
        ca_url: args.ca_url,
        key_name: args.key_name,
        retry_guidance: RETRY_GUIDANCE.to_owned(),
    })
}

pub fn delete_key(args: DeleteKeyArgs) -> Result<()> {
    artifacts::delete_key(artifacts::DeleteKeyArgs {
        output_dir: args.output_dir,
        confirm_key_name: args.confirm_key_name,
    })
}

pub fn load_request(output_dir: &Path) -> Result<RequestMetadata> {
    artifacts::load_request(output_dir)
}

pub fn validate_stored_request(output_dir: &Path, metadata: &RequestMetadata) -> Result<Vec<u8>> {
    artifacts::validate_stored_request(output_dir, metadata)
}

pub fn deletion_status(output_dir: &Path, metadata: &RequestMetadata) -> Result<&'static str> {
    artifacts::deletion_status(output_dir, metadata)
}
