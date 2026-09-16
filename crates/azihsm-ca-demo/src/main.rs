//! Command-line entry point for the AziHSM TLS enrollment demonstration.

fn main() {
    if let Err(error) = azihsm_ca_demo::main_entry() {
        tracing::error!(
            event = "command_failed",
            class = ?error.class(),
            message = "The demo command stopped safely; review the bounded error and unchanged public transcript."
        );
        eprintln!("{error}");
        std::process::exit(error.exit_code().into());
    }
}
