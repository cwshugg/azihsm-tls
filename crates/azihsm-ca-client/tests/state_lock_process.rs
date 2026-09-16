//! Cross-process proof for the shared application state lock.

#![cfg(windows)]

use azihsm_ca_client::state_lock::StateLock;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn shared_lock_contends_across_processes_and_recovers() {
    let directory = std::env::current_dir()
        .unwrap_or_else(|error| panic!("{error}"))
        .join("target")
        .join(format!("shared-lock-process-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let held = StateLock::acquire(&directory).unwrap_or_else(|error| panic!("{error}"));
    run_child(&directory, true);
    drop(held);
    run_child(&directory, false);
    std::fs::remove_dir_all(directory).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn child_reports_lock_result() {
    let Some(path) = std::env::var_os("AZIHSM_LOCK_TEST_PATH") else {
        return;
    };
    let expected_locked = std::env::var("AZIHSM_LOCK_TEST_EXPECTED")
        .unwrap_or_else(|error| panic!("{error}"))
        == "locked";
    let result = StateLock::acquire(&PathBuf::from(path));
    assert_eq!(result.is_err(), expected_locked);
}

fn run_child(directory: &std::path::Path, expected_locked: bool) {
    let status = Command::new(std::env::current_exe().unwrap_or_else(|error| panic!("{error}")))
        .args(["--exact", "child_reports_lock_result"])
        .env("AZIHSM_LOCK_TEST_PATH", directory)
        .env(
            "AZIHSM_LOCK_TEST_EXPECTED",
            if expected_locked {
                "locked"
            } else {
                "available"
            },
        )
        .status()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(status.success());
}
