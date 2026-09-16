//! AziHSM-backed TLS certificate enrollment workflow.

#[cfg(not(windows))]
compile_error!("azihsm-ca-demo is Windows-only");

pub mod cli;
pub mod logging;
pub mod workflow;

pub use azihsm_ca_client::transcript;
pub use azihsm_ncrypt::{Error, ErrorClass, Result};

use cli::Command;

/// Executes one complete demo command.
pub fn execute(command: Command) -> Result<()> {
    match command {
        Command::Create(args) => workflow::create(args),
        Command::Retry(args) => workflow::retry(args),
        Command::Show(args) => workflow::show(args),
        Command::DeleteKey(args) => workflow::delete_key(args),
    }
}
