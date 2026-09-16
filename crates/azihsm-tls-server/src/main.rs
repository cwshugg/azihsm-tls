//! Binary entry point for `azihsm-tls-server`.

fn main() {
    if let Err(error) = azihsm_tls_server::main_entry() {
        tracing::error!(
            event = "command_failed",
            message = "The command stopped safely; review the bounded error and preceding stage description."
        );
        eprintln!("{error}");
        std::process::exit(1);
    }
}
