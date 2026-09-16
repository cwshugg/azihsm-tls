//! Top-level command execution.

use crate::authority;
use crate::cli::{Command, parse};
use crate::error::Result;
use crate::state::StateLock;
use std::ffi::OsString;

pub fn run<I>(arguments: I) -> Result<Option<String>>
where
    I: IntoIterator<Item = OsString>,
{
    let command = parse(arguments)?;
    crate::logging::init(matches!(command, Command::Serve(_)))?;
    match command {
        Command::Help(message) => Ok(Some(message)),
        Command::Init(args) => {
            authority::initialize(args)?;
            Ok(None)
        }
        Command::Inspect { state_dir } => authority::inspect(&state_dir).map(Some),
        Command::Quarantine {
            state_dir,
            issuance_id,
        } => {
            authority::quarantine(&state_dir, &issuance_id)?;
            Ok(None)
        }
        Command::Serve(args) => {
            tracing::info!(
                event = "server_starting",
                max_connections = args.max_connections,
                allow_dns_count = args.allow_dns.len(),
                allow_ip_count = args.allow_ip.len(),
                leaf_valid_hours = args.leaf_valid_hours
            );
            crate::state::validate_state_format(&args.state_dir)?;
            tracing::info!(
                event = "state_format_validated",
                version = crate::state::STATE_FORMAT_VERSION,
                producer = crate::state::STATE_PRODUCER
            );
            let _lock = StateLock::acquire(&args.state_dir, false)?;
            let loaded = authority::load_for_serve(&args.state_dir)?;
            tracing::info!(
                event = "authority_opened",
                authority_id = loaded.authority.authority_id
            );
            crate::http::serve(args, loaded)?;
            Ok(None)
        }
    }
}
