# AziHSM TLS Client Usage

`azihsm-tls-client` is the client side of the AziHSM TLS demonstration. It connects to
a TLS server, validates the server certificate **strictly against a supplied CA
root**, and exchanges a message. It has no AziHSM or KSP dependency — the client
only trusts the CA root that issued the server certificate — so it is
cross-platform and can be developed and tested without hardware. For
implementation details, see the [crate README](../crates/azihsm-tls-client/README.md).

## Role in the demonstration

In one-way TLS, the server holds the AziHSM-backed private key and presents a
certificate issued by the [`azihsm-ca`](../crates/azihsm-ca) mock CA. The client
does not enroll or hold any key; it installs the CA root as its only trust
anchor and validates the server certificate locally.

```
azihsm-ca (root)  --signs-->  server certificate
                                     |
azihsm-tls-client  --trusts CA root-->  validates server cert  -->  exchanges message
```

## Prerequisites

* Rust `1.88` or newer.
* The CA root certificate (PEM) produced by `azihsm-ca`.
* A reachable TLS server presenting a certificate that chains to that root, with
  a matching `--server-name`.

## Build

From the repository root in PowerShell:

```powershell
cd crates
cargo build -p azihsm-tls-client
```

## Usage

```powershell
azihsm-tls-client `
  --connect server.example:8443 `
  --ca-root C:\azihsm-demo\ca-root.pem `
  --server-name server.example `
  --message "hello from azihsm-tls-client"
```

On success the client prints the number of bytes the server returned followed by
the response, and exits 0. On failure it prints an error and exits with a
class-specific code:

| Code | Meaning |
|------|---------|
| 2 | Usage error (invalid arguments) |
| 3 | I/O error (connect, read, or write) |
| 4 | TLS setup error |
| 5 | Trust error (bad CA root, or the server did not chain to it) |

## Security boundary

* The client trusts **only** the certificates in `--ca-root`; the system trust
  store is not consulted.
* A server whose certificate does not chain to that root is rejected before any
  application data is exchanged (exit code 5).
* TLS 1.2 and 1.3 only; the hostname in `--server-name` is validated against the
  certificate.

## Tests

```powershell
cargo test -p azihsm-tls-client
```

No network or hardware is required. Coverage includes CLI validation, CA-root
loading errors, and a full handshake against an in-process rustls echo server:
a certificate that chains to the trusted root succeeds, and one signed by an
untrusted root is rejected.
