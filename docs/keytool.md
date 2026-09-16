# AziHSM keytool Usage

`keytool` is a Windows-only CLI that initializes and exercises a **named,
current-user AziHSM P-256 key** — the key a TLS server would later use for its
handshake signatures. It is the foundational, "key-management only" step: it
does not open sockets or run a TLS handshake. It builds on the shared
[`azihsm-ncrypt`](../crates/azihsm-ncrypt) crate, so the same key path is reused
by the eventual TLS server.

## Purpose

A TLS server on Windows does not receive a key handle; Schannel looks up the
server certificate, reads its key container **name**, and calls
`NCryptOpenKey(name)` from a different process. That makes named and
cross-process key access the gating capability. `keytool` proves that path in
isolation:

1. create a named key inside AziHSM (one process),
2. reopen it by name and sign from a **separate process**,
3. export its public key for certificate enrollment.

## Security and cryptographic boundary

* Key creation, finalization, opening, signing, and deletion all use Windows
  NCrypt with the registered
  `Microsoft Azure Integrated HSM Key Storage Provider`.
* The private key is never exported. Only the ECDSA P-256 public blob leaves the
  provider (for CSR / certificate issuance).
* Keys are current-Windows-user scoped: `keytool` must run as the same user that
  initialized the named key.

## Prerequisites

* Windows with the AziHSM KSP installed and registered under the exact provider
  name shown above.
* Rust `1.88` or newer and the `x86_64-pc-windows-msvc` target.
* RSA is not supported on-device; the key is ECDSA P-256.

## Build

From the repository root in PowerShell:

```powershell
cd crates
cargo build -p keytool
```

## Commands

| Command | Description |
|---------|-------------|
| `keytool init --name <NAME>` | Create and finalize a named P-256 key, then run a sign/verify self-test and print the public key. |
| `keytool open --name <NAME>` | Open an existing named key and sign a fresh challenge (proves cross-process access). |
| `keytool public --name <NAME>` | Print the exported public key (hex) for certificate enrollment. |
| `keytool delete --name <NAME>` | Delete a named key. |

Key names are limited to `[A-Za-z0-9._-]` and 128 bytes.

### Example: create, then open from another process

```powershell
cargo run -p keytool -- init --name tls-server-key
# ... later, in a separate shell / process ...
cargo run -p keytool -- open --name tls-server-key
cargo run -p keytool -- public --name tls-server-key
```

A successful `open` after `init` in a distinct process is the cross-process
proof the TLS server depends on.

## Logging

Set `RUST_LOG` to one of `off`, `error`, `warn`, `info` (default), `debug`, or
`trace`. Logs go to stderr; command output goes to stdout.

## Tests

```powershell
# CLI contract tests (no hardware required)
cargo test -p keytool

# Operator-gated live round-trip on a registered AziHSM VM
cargo test -p keytool -- --ignored
```

The live test runs `init → public → open → delete → reopen` across separate
processes and asserts the key is reachable cross-process and gone after
deletion.
