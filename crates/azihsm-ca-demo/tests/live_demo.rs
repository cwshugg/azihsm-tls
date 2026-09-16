//! Operator-gated end-to-end demo enrollment with unique named-key cleanup.

#![cfg(windows)]

use std::env;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const EXE: &str = env!("CARGO_BIN_EXE_azihsm-ca-demo");

#[test]
#[ignore = "requires registered AziHSM provider and a currently running live CA"]
fn create_retry_show_and_delete_unique_named_key() {
    let ca_url = env::var("AZIHSM_DEMO_LIVE_CA_URL")
        .unwrap_or_else(|_| panic!("BLOCKED: set AZIHSM_DEMO_LIVE_CA_URL"));
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("{error}"))
        .as_nanos();
    let key_name = format!("azihsm-ca-demo-live-{id:x}");
    let output = env::current_dir()
        .unwrap_or_else(|error| panic!("{error}"))
        .join("target")
        .join(format!("demo-live-{id:x}"));
    let output_text = output
        .to_str()
        .unwrap_or_else(|| panic!("test path is not Unicode"));
    run(&[
        "create",
        "--output-dir",
        output_text,
        "--subject-cn",
        "server.demo.internal",
        "--dns",
        "server.demo.internal",
        "--ca-url",
        &ca_url,
        "--acknowledge-plain-http",
        "--key-name",
        &key_name,
    ]);
    run(&[
        "retry",
        "--output-dir",
        output_text,
        "--acknowledge-plain-http",
    ]);
    run(&["show", "--output-dir", output_text]);
    run(&[
        "delete-key",
        "--output-dir",
        output_text,
        "--confirm-key-name",
        &key_name,
    ]);
    assert!(output.join("deletion-intent.json").exists());
    assert!(output.join("deletion-record.json").exists());
    fs::remove_file(output.join("deletion-record.json")).unwrap_or_else(|error| panic!("{error}"));
    run(&["show", "--output-dir", output_text]);
    run(&[
        "delete-key",
        "--output-dir",
        output_text,
        "--confirm-key-name",
        &key_name,
    ]);
    assert!(output.join("deletion-record.json").exists());
    fs::remove_dir_all(output).unwrap_or_else(|error| panic!("{error}"));
}

fn run(arguments: &[&str]) {
    let status = Command::new(EXE)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(status.success(), "command failed with {status}");
}
