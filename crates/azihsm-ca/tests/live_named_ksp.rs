//! Explicit live named-key acceptance against a uniquely owned test key.

#![cfg(windows)]

use azihsm_ca::policy::PROVIDER_NAME;
use azihsm_ca::state::{
    Authority, IssuanceIntent, SCHEMA_VERSION, SerialReservation, create_protected_dir,
    durable_bytes, durable_json,
};
use azihsm_ca::win::ncrypt::AziProvider;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use windows_sys::Win32::Security::Cryptography::NCryptDeleteKey;

const EXE: &str = env!("CARGO_BIN_EXE_azihsm-ca");

#[test]
#[ignore = "requires registered named-key AziHSM provider"]
fn init_reopen_inspect_and_checked_delete() {
    if env::var("AZIHSM_LIVE_TEST").as_deref() != Ok("mock") {
        panic!("BLOCKED: set AZIHSM_LIVE_TEST=mock");
    }

    let id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("{error}"))
            .as_nanos()
    );
    let key_name = format!("azihsm-ca-live-{id}");
    let state = env::current_dir()
        .unwrap_or_else(|error| panic!("{error}"))
        .join("target")
        .join(format!("live-state-{id}"));
    std::fs::create_dir_all(
        state
            .parent()
            .unwrap_or_else(|| panic!("state path has no parent")),
    )
    .unwrap_or_else(|error| panic!("cannot create live-test parent: {error}"));
    let init = Command::new(EXE)
        .args([
            "init",
            "--state-dir",
            state
                .to_str()
                .unwrap_or_else(|| panic!("state path is not Unicode")),
            "--provider",
            PROVIDER_NAME,
            "--key-name",
            &key_name,
            "--root-valid-days",
            "30",
        ])
        .status()
        .unwrap_or_else(|error| panic!("init failed: {error}"));
    assert!(init.success(), "live init failed with {init}");
    let inspect = Command::new(EXE)
        .args([
            "inspect",
            "--state-dir",
            state
                .to_str()
                .unwrap_or_else(|| panic!("state path is not Unicode")),
        ])
        .status()
        .unwrap_or_else(|error| panic!("inspect failed: {error}"));
    assert!(inspect.success(), "live inspect failed with {inspect}");
    let provider = AziProvider::open_named(PROVIDER_NAME).unwrap_or_else(|error| panic!("{error}"));
    let mut key = provider
        .open_key(&key_name)
        .unwrap_or_else(|status| panic!("reopen failed: 0x{:08x}", status as u32));
    key.kat().unwrap_or_else(|error| panic!("{error}"));
    // SAFETY: the collision-resistant key name and state are owned by this test.
    let status = unsafe { NCryptDeleteKey(key.key.0, 0) };
    assert!(
        status >= 0,
        "checked delete failed: 0x{:08x}",
        status as u32
    );
    key.key.disarm();
    assert!(
        provider.open_key(&key_name).is_err(),
        "test key still opens"
    );
    std::fs::remove_dir_all(&state).unwrap_or_else(|error| panic!("{error}"));
    println!("PASS: init, fresh-process inspect, reopen, KAT, and checked unique-key deletion");
}

#[test]
#[ignore = "requires registered named-key AziHSM provider"]
fn reconcile_adopts_root_and_publication_staging_and_terminal_replay() {
    if env::var("AZIHSM_LIVE_TEST").as_deref() != Ok("mock") {
        panic!("BLOCKED: set AZIHSM_LIVE_TEST=mock");
    }

    {
        let id = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|error| panic!("{error}"))
                .as_nanos()
        );
        let key_name = format!("azihsm-ca-precommit-{id}");
        let state = env::current_dir()
            .unwrap_or_else(|error| panic!("{error}"))
            .join("target")
            .join(format!("precommit-state-{id}"));
        run(&[
            "init",
            "--state-dir",
            text(&state),
            "--provider",
            PROVIDER_NAME,
            "--key-name",
            &key_name,
            "--root-valid-days",
            "30",
        ]);
        let authority: Authority = serde_json::from_slice(
            &fs::read(state.join("authority.json")).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let empty_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        create_protected_dir(&state.join("issuances").join(empty_id))
            .unwrap_or_else(|error| panic!("{error}"));
        run_failure(&["inspect", "--state-dir", text(&state)]);
        run(&[
            "quarantine-issuance",
            "--state-dir",
            text(&state),
            "--issuance-id",
            empty_id,
        ]);
        run(&["inspect", "--state-dir", text(&state)]);

        let intent_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let intent_dir = state.join("issuances").join(intent_id);
        create_protected_dir(&intent_dir).unwrap_or_else(|error| panic!("{error}"));
        durable_json(
            &intent_dir.join("intent.json"),
            &IssuanceIntent {
                schema_version: SCHEMA_VERSION,
                issuance_id: intent_id.to_owned(),
                authority_id: authority.authority_id.clone(),
                serial: "10".to_owned(),
                correlation_id: "correlation".to_owned(),
                idempotency_key_hash: "intent-key".to_owned(),
                request_hash: "intent-request".to_owned(),
                csr_sha256: "csr".to_owned(),
                spki_sha256: "spki".to_owned(),
                dns_sans: vec!["server.demo.internal".to_owned()],
                ip_sans: Vec::new(),
                not_before: "2026-01-01T00:00:00Z".to_owned(),
                not_after: "2026-01-02T00:00:00Z".to_owned(),
                profile: "server-auth-v1".to_owned(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        fs::rename(
            intent_dir.join("intent.json"),
            intent_dir.join(".intent.json.pending"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let reservation_path = state.join("serial-reservations").join("10.json");
        durable_json(
            &reservation_path,
            &SerialReservation {
                schema_version: SCHEMA_VERSION,
                serial: "10".to_owned(),
                issuance_id: intent_id.to_owned(),
                authority_id: authority.authority_id.clone(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        fs::rename(
            &reservation_path,
            state.join("serial-reservations").join(".10.json.pending"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        durable_bytes(&intent_dir.join("certificate.der"), b"signed-artifact")
            .unwrap_or_else(|error| panic!("{error}"));
        run_failure(&["inspect", "--state-dir", text(&state)]);
        assert!(intent_dir.join("intent.json").exists());
        assert!(reservation_path.exists());
        run(&[
            "quarantine-issuance",
            "--state-dir",
            text(&state),
            "--issuance-id",
            intent_id,
        ]);
        run(&["inspect", "--state-dir", text(&state)]);

        let orphan_id = "cccccccccccccccccccccccccccccccc";
        durable_json(
            &state.join("serial-reservations").join("20.json"),
            &SerialReservation {
                schema_version: SCHEMA_VERSION,
                serial: "20".to_owned(),
                issuance_id: orphan_id.to_owned(),
                authority_id: authority.authority_id,
                created_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        run_failure(&["inspect", "--state-dir", text(&state)]);
        run(&[
            "quarantine-issuance",
            "--state-dir",
            text(&state),
            "--issuance-id",
            orphan_id,
        ]);
        run(&["inspect", "--state-dir", text(&state)]);

        delete_test_key(&key_name);
        fs::remove_dir_all(&state).unwrap_or_else(|error| panic!("{error}"));
        println!("PASS: empty, intent-only, and orphan-reservation states quarantined");
    }
    let id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("{error}"))
            .as_nanos()
    );
    let key_name = format!("azihsm-ca-reconcile-{id}");
    let state = env::current_dir()
        .unwrap_or_else(|error| panic!("{error}"))
        .join("target")
        .join(format!("reconcile-state-{id}"));
    run(&[
        "init",
        "--state-dir",
        text(&state),
        "--provider",
        PROVIDER_NAME,
        "--key-name",
        &key_name,
        "--root-valid-days",
        "30",
    ]);
    let authority_bytes =
        fs::read(state.join("authority.json")).unwrap_or_else(|error| panic!("{error}"));
    let authority: serde_json::Value =
        serde_json::from_slice(&authority_bytes).unwrap_or_else(|error| panic!("{error}"));
    let operation_id = authority["init_operation_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing operation ID"));
    let root_bytes = fs::read(state.join("root.der")).unwrap_or_else(|error| panic!("{error}"));
    let completed = state
        .join("init-intents")
        .join("archive")
        .join("completed")
        .join(operation_id);
    let active = state.join("init-intents").join("active").join(operation_id);
    fs::rename(&completed, &active).unwrap_or_else(|error| panic!("{error}"));
    for entry in fs::read_dir(&active).unwrap_or_else(|error| panic!("{error}")) {
        let path = entry.unwrap_or_else(|error| panic!("{error}")).path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.len() != 11
            || !name.ends_with(".json")
            || !name[..6].bytes().all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap_or_else(|error| panic!("{error}")))
                .unwrap_or_else(|error| panic!("{error}"));
        if matches!(
            value["phase"].as_str(),
            Some("root_validated" | "authority_published" | "completed")
        ) {
            fs::remove_file(path).unwrap_or_else(|error| panic!("{error}"));
        }
    }
    fs::rename(active.join("root.der"), active.join(".root.der.pending"))
        .unwrap_or_else(|error| panic!("{error}"));
    fs::rename(
        active.join("publication.json"),
        active.join(".publication.json.pending"),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    fs::remove_file(state.join("authority.json")).unwrap_or_else(|error| panic!("{error}"));
    fs::remove_file(state.join("root.der")).unwrap_or_else(|error| panic!("{error}"));
    for entry in fs::read_dir(state.join("audit")).unwrap_or_else(|error| panic!("{error}")) {
        fs::remove_file(entry.unwrap_or_else(|error| panic!("{error}")).path())
            .unwrap_or_else(|error| panic!("{error}"));
    }
    azihsm_ca::state::durable_bytes(&state.join("root.der"), &root_bytes)
        .unwrap_or_else(|error| panic!("{error}"));
    run(&[
        "init",
        "--state-dir",
        text(&state),
        "--reconcile-intent",
        operation_id,
    ]);
    assert_eq!(
        fs::read(state.join("root.der")).unwrap_or_else(|error| panic!("{error}")),
        root_bytes
    );
    assert_eq!(
        fs::read(state.join("authority.json")).unwrap_or_else(|error| panic!("{error}")),
        authority_bytes
    );
    run(&[
        "init",
        "--state-dir",
        text(&state),
        "--reconcile-intent",
        operation_id,
    ]);
    assert_eq!(
        fs::read_dir(state.join("audit"))
            .unwrap_or_else(|error| panic!("{error}"))
            .count(),
        1
    );
    run(&["inspect", "--state-dir", text(&state)]);
    delete_test_key(&key_name);
    fs::remove_dir_all(&state).unwrap_or_else(|error| panic!("{error}"));
    println!("PASS: root and publication staging recovered, terminal replay kept one audit event");
}

#[test]
#[ignore = "operator-invoked cleanup for a failed test-owned server state"]
fn cleanup_failed_test_authority() {
    let state = PathBuf::from(
        env::var("AZIHSM_TEST_CLEANUP_STATE")
            .unwrap_or_else(|_| panic!("BLOCKED: missing AZIHSM_TEST_CLEANUP_STATE")),
    );
    assert!(
        state.to_string_lossy().contains("server-restart-")
            || state.to_string_lossy().contains("reconcile-state-")
            || state.to_string_lossy().contains("live-state-")
            || state.to_string_lossy().contains("precommit-state-"),
        "refusing non-test state"
    );
    let authority_bytes = fs::read(state.join("authority.json")).unwrap_or_else(|_| {
        let active = state.join("init-intents").join("active");
        let operation = fs::read_dir(active)
            .unwrap_or_else(|error| panic!("{error}"))
            .next()
            .unwrap_or_else(|| panic!("active journal missing"))
            .unwrap_or_else(|error| panic!("{error}"))
            .path();
        fs::read(operation.join("publication.json")).unwrap_or_else(|error| panic!("{error}"))
    });
    let mut authority: serde_json::Value =
        serde_json::from_slice(&authority_bytes).unwrap_or_else(|error| panic!("{error}"));
    if authority.get("authority").is_some() {
        authority = authority["authority"].clone();
    }
    let key_name = authority["key_name"]
        .as_str()
        .unwrap_or_else(|| panic!("authority key name missing"));
    assert!(
        key_name.starts_with("azihsm-ca-http-")
            || key_name.starts_with("azihsm-ca-reconcile-")
            || key_name.starts_with("azihsm-ca-live-")
            || key_name.starts_with("azihsm-ca-precommit-"),
        "refusing non-test key"
    );
    let provider = AziProvider::open_named(PROVIDER_NAME).unwrap_or_else(|error| panic!("{error}"));
    let mut key = provider
        .open_key(key_name)
        .unwrap_or_else(|status| panic!("reopen failed: 0x{:08x}", status as u32));
    // SAFETY: both state path and collision-resistant key prefix prove test ownership.
    let status = unsafe { NCryptDeleteKey(key.key.0, 0) };
    assert!(status >= 0, "delete failed: 0x{:08x}", status as u32);
    key.key.disarm();
    let removal = if state.to_string_lossy().contains("server-restart-") {
        state
            .parent()
            .unwrap_or_else(|| panic!("test state has no parent"))
            .to_path_buf()
    } else {
        state
    };
    fs::remove_dir_all(removal).unwrap_or_else(|error| panic!("{error}"));
}

fn run(arguments: &[&str]) {
    let status = Command::new(EXE)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(status.success(), "command failed with {status}");
}

fn run_failure(arguments: &[&str]) {
    let status = Command::new(EXE)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!status.success(), "command unexpectedly succeeded");
}

fn delete_test_key(key_name: &str) {
    assert!(
        key_name.starts_with("azihsm-ca-reconcile-")
            || key_name.starts_with("azihsm-ca-precommit-"),
        "refusing non-test key"
    );
    let provider = AziProvider::open_named(PROVIDER_NAME).unwrap_or_else(|error| panic!("{error}"));
    let mut key = provider
        .open_key(key_name)
        .unwrap_or_else(|status| panic!("reopen failed: 0x{:08x}", status as u32));
    // SAFETY: the collision-resistant name is owned by this test.
    let status = unsafe { NCryptDeleteKey(key.key.0, 0) };
    assert!(status >= 0, "delete failed: 0x{:08x}", status as u32);
    key.key.disarm();
}

fn text(path: &std::path::Path) -> &str {
    path.to_str()
        .unwrap_or_else(|| panic!("test path is not Unicode"))
}
