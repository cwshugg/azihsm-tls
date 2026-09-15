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
    match parse(arguments)? {
        Command::Help => Ok(Some(crate::cli::help())),
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
            let _lock = StateLock::acquire(&args.state_dir, false)?;
            let loaded = authority::load_for_serve(&args.state_dir)?;
            crate::http::serve(args, loaded)?;
            Ok(None)
        }
    }
}
