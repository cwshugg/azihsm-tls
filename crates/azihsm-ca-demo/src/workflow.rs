//! Demo command adapters for shared artifact operations.

use crate::Result;
use crate::cli::{CreateArgs, DeleteKeyArgs, OutputArgs, RetryArgs};
use azihsm_ca_client::{artifacts, state_lock::StateLock};

const RETRY_GUIDANCE: &str = "After restarting or reconfiguring the CA, run `azihsm-ca-demo retry \
    --output-dir <same-directory> --acknowledge-plain-http`. Retry reuses the existing AziHSM key, \
    CSR, and idempotency key; do not run create again.";

pub fn create(args: CreateArgs) -> Result<()> {
    let _lock = StateLock::acquire(&args.output_dir)?;
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

pub fn retry(args: RetryArgs) -> Result<()> {
    let _lock = StateLock::acquire(&args.output_dir)?;
    artifacts::retry(artifacts::RetryArgs {
        output_dir: args.output_dir,
        retry_guidance: RETRY_GUIDANCE.to_owned(),
    })
}

pub fn show(args: OutputArgs) -> Result<()> {
    let _lock = StateLock::acquire(&args.output_dir)?;
    artifacts::show(artifacts::OutputArgs {
        output_dir: args.output_dir,
    })
}

pub fn delete_key(args: DeleteKeyArgs) -> Result<()> {
    let _lock = StateLock::acquire(&args.output_dir)?;
    artifacts::delete_key(artifacts::DeleteKeyArgs {
        output_dir: args.output_dir,
        confirm_key_name: args.confirm_key_name,
    })
}
