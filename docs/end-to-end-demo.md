# End-to-End Demo: AziHSM TLS (CA + Server + Client)

This runbook reproduces the full one-way TLS scenario on real AziHSM hardware:
a TLS server whose private key lives in AziHSM, a certificate issued by an
AziHSM-backed CA, and a client that validates the server and exchanges a
message. All PowerShell commands are single-line.

> Demonstration only, not production. The CA is contacted over plain HTTP and
> the trust root is self-managed; there is no confidentiality, endpoint
> authentication, or revocation. Use isolated test machines only.

## Prerequisites

* Windows machine(s) with an attached AziHSM device and the AziHSM KSP
  registered (named-key build).
* Visual Studio Build Tools with "Desktop development with C++" (provides
  `link.exe`).
* A repository checkout. Run commands from the repository root.

Placement:

* `azihsm-ca` and `azihsm-tls-server` need AziHSM; they may share one machine
  (distinct ports, state dirs, and key names) or run on separate machines.
* `azihsm-tls-client` needs no AziHSM and can run anywhere.

Paths below use `E:\azihsm-demo` only as an example. Use any **local absolute**
path on any drive; `azihsm-ca` requires a local absolute path (no relative,
UNC, or network paths).

## 0. Build

```powershell
cargo build --locked --manifest-path .\crates\Cargo.toml -p azihsm-ca -p azihsm-tls-server -p azihsm-tls-client --release --target x86_64-pc-windows-msvc
```

## 1. Start the CA (terminal 1)

```powershell
$CaExe = '.\crates\target\x86_64-pc-windows-msvc\release\azihsm-ca.exe'
$CaState = 'E:\azihsm-demo\ca-state'
New-Item -ItemType Directory -Force E:\azihsm-demo | Out-Null
& $CaExe init --state-dir $CaState --provider 'Microsoft Azure Integrated HSM Key Storage Provider' --key-name ('azihsm-ca-' + [Guid]::NewGuid().ToString('N'))
& $CaExe serve --state-dir $CaState --listen '127.0.0.1:8080' --allow-dns 'server.demo'
```

Leave it running. Wait for `readiness_changed ready=true`. Create the state
directory's parent yourself; let the CA create and protect `ca-state`.

## 2. Start the TLS server (terminal 2)

```powershell
$ServerExe = '.\crates\target\x86_64-pc-windows-msvc\release\azihsm-tls-server.exe'
& $ServerExe run --state-dir 'E:\azihsm-demo\tls-server' --listen '127.0.0.1:8443' --dns 'server.demo' --ca-url 'http://127.0.0.1:8080' --acknowledge-plain-http
```

The server creates its own named key in AziHSM, sends a CSR to the CA, and
serves TLS. The CA terminal logs `enrollment_accepted`.

## 3. Export the CA root as PEM (terminal 3)

The client validates against a PEM anchor; the CA writes DER, so convert once:

```powershell
certutil -encode E:\azihsm-demo\ca-state\root.der E:\azihsm-demo\ca-root.pem
```

## 4. Run the client (terminal 3)

```powershell
.\crates\target\x86_64-pc-windows-msvc\release\azihsm-tls-client.exe --connect 127.0.0.1:8443 --ca-root E:\azihsm-demo\ca-root.pem --server-name server.demo --message hello
```

Expected:

```text
handshake ok; server replied 24 bytes
azihsm-tls-server: hello
```

`--connect` is the address; `--server-name` is the certificate name to validate
(no hosts-file mapping needed).

## What this proves

* The CA private key and the TLS server private key both stay inside AziHSM.
* The handshake `CertificateVerify` signature is produced inside the device.
* The client trusts only the supplied CA root and validates the server name.

## Where the files and keys live

* **Named keys** are persisted as device-wrapped (masked) blobs on disk at
  `%LOCALAPPDATA%\Microsoft\azihsmguest\keys`, one per key name; the private
  key material stays inside the AziHSM device. Inspect state through the tools:
  `& $CaExe inspect --state-dir $CaState` and
  `& $ServerExe show --state-dir E:\azihsm-demo\tls-server`. The key names also
  appear in the startup logs.
* **CA state** (`E:\azihsm-demo\ca-state`): `root.der` (public root for client
  trust), issuance journals, and audit records.
* **Server state** (`E:\azihsm-demo\tls-server`): the cached issued certificate
  and identity metadata.
* **Client trust anchor**: `E:\azihsm-demo\ca-root.pem`, produced in step 3.

## Cleanup

Stop the CA and server with Ctrl+C, then remove the demo directory:

```powershell
Remove-Item -Recurse -Force E:\azihsm-demo
```

Removing `E:\azihsm-demo` deletes only the local state (root, certificate,
journals), not the named keys.
