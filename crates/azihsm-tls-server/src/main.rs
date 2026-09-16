//! Binary entry point for `azihsm-tls-server`.

fn main() {
    if let Err(error) = azihsm_tls_server::main_entry() {
        tracing::error!(event = "command_failed");
        eprintln!("{error}");
        std::process::exit(1);
    }
}
