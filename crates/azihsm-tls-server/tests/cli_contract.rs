//! Public CLI contract tests.

use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_azihsm-tls-server");

#[test]
fn help_lists_exact_commands_and_run_defaults() {
    let output = Command::new(EXE)
        .arg("--help")
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("run"));
    assert!(text.contains("show"));
    assert!(text.contains("delete-key"));
    assert!(!text.contains("rsa"));

    let output = Command::new(EXE)
        .args(["run", "--help"])
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    for required in [
        "--state-dir",
        "--listen",
        "127.0.0.1:8443",
        "--dns",
        "--ip",
        "--ca-url",
        "--acknowledge-plain-http",
    ] {
        assert!(text.contains(required), "missing {required}");
    }
}
