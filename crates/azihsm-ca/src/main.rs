//! Command-line entry point for the persistent demonstration CA.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    match azihsm_ca::operations::run(std::env::args_os()) {
        Ok(Some(message)) => {
            print!("{message}");
            std::process::ExitCode::SUCCESS
        }
        Ok(None) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(not(windows))]
fn main() {
    compile_error!("azihsm-ca is Windows-only");
}
