# `azihsm-tls-client`

`azihsm-tls-client` is a minimal TLS client for the AziHSM TLS demonstration. It
connects to a server, validates the server certificate **only** against a
supplied CA root (not the system trust store), and exchanges a single message.

It has no AziHSM or KSP dependency: the client only needs to trust the CA root
that issued the server certificate, so it is cross-platform and testable without
hardware. rustls (ring provider) implements TLS 1.2/1.3; `rustls-pemfile` loads
the CA root; clap implements the CLI. For usage and demo steps, see the
[TLS client guide](../../docs/azihsm-tls-client.md).

## Command line

```text
azihsm-tls-client --help
azihsm-tls-client --connect HOST:PORT --ca-root ROOT_PEM --server-name NAME [--message TEXT]
```

* `--connect` - server address as `host:port`.
* `--ca-root` - PEM file whose certificates are the only trusted anchors.
* `--server-name` - expected server name, used for SNI and certificate validation.
* `--message` - text to send after the handshake (defaults to a fixed greeting).

## Wire protocol

After the handshake, the message is sent as a single length-prefixed frame (a
4-byte big-endian length followed by the payload), and the reply is read the
same way. This matches the `azihsm-tls-server` framing, so the client
interoperates with it directly.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Handshake succeeded and the message was exchanged |
| 2 | Usage error (invalid arguments) |
| 3 | I/O error (connect, read, or write) |
| 4 | TLS setup error |
| 5 | Trust error (bad CA root, or the server did not chain to it) |

## Build and test

From the top-level `crates/` workspace:

```powershell
cargo build -p azihsm-tls-client
cargo fmt -p azihsm-tls-client -- --check
cargo clippy -p azihsm-tls-client --all-targets
cargo test -p azihsm-tls-client
```

The tests require no network or hardware: they cover CLI validation, CA-root
loading errors, and a full handshake against an in-process rustls echo server
(valid chain succeeds; an untrusted root is rejected).

## Logging

Set `RUST_LOG` to one of `off`, `error`, `warn`, `info` (default), `debug`, or
`trace`. Logs go to stderr; command output goes to stdout.
