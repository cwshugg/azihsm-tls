# `azihsm-ca`

`azihsm-ca` is a persistent, Windows-only demonstration certificate authority.
It stores one current-user named ECDSA P-256 CA key in the registered Microsoft
Azure Integrated HSM Key Storage Provider and signs through Windows NCrypt and
Crypt32. BCrypt supplies hashing, randomness, public-key verification, and
known-answer tests. The product does not use OpenSSL, and OpenSSL is prohibited
for product operation and validation.

## Accepted demonstration risks

This is not a production or public CA. The following five risks are explicitly
accepted for the fixed demonstration scope:

1. Any reachable caller can obtain a certificate for an allowlisted SAN using
   its own key.
2. Any process running as the CA account can reopen and use the named key,
   bypassing policy, records, limits, and audit.
3. Coherent local rollback, replacement, or deletion may be undetectable;
   status and audit may be incomplete or inaccurate.
4. Plain HTTP provides no confidentiality, integrity, or endpoint
   authentication; binding and firewall rules reduce reachability only.
5. Revocation, CRLs, and OCSP are not provided; certificates can remain usable
   until expiry or trust removal.

The implementation does not expand scope into API TLS, authentication, remote
ledgers, client enrollment, or revocation.

## Build

Run from the top-level `crates\` workspace:

```powershell
cargo test --locked -p azihsm-ca --test windows_bindings_smoke `
    --target x86_64-pc-windows-msvc
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets `
    --target x86_64-pc-windows-msvc -- -D warnings
cargo test --locked --workspace --all-targets `
    --target x86_64-pc-windows-msvc --no-fail-fast
cargo build --locked --workspace `
    --target x86_64-pc-windows-msvc --release
```

## Command line

```text
azihsm-ca --help
azihsm-ca init --state-dir ABSOLUTE_PATH \
  --provider "Microsoft Azure Integrated HSM Key Storage Provider" \
  --key-name NAME [--root-valid-days 3650]
azihsm-ca init --state-dir ABSOLUTE_PATH --reconcile-intent HEX32
azihsm-ca init --state-dir ABSOLUTE_PATH --abandon-intent HEX32
azihsm-ca serve --state-dir ABSOLUTE_PATH [--listen 127.0.0.1:8080] \
  [--allow-dns NAME]... [--allow-ip ADDRESS]... [OPTIONS]
azihsm-ca inspect --state-dir ABSOLUTE_PATH
azihsm-ca quarantine-issuance --state-dir ABSOLUTE_PATH --issuance-id HEX32
```

At least one exact DNS or IP SAN is required for `serve`. Non-loopback binding
requires `--allow-insecure-demo-http-nonloopback`. DNS authorization is exact,
lowercase ASCII LDH matching; there are no wildcard or suffix semantics.

Exit codes are `0` success, `2` usage, `3` state, `4` provider/key, `5` pending
initialization, `6` identity/profile/cryptographic mismatch, `7` HTTP runtime,
`8` issuance/durability, `10` already initialized, `11` state busy, and `12`
recovery or quarantine refused. Exit `9` is reserved and is not emitted by this
version.

## Initialization and recovery

Initialization acquires `authority.lock`, proves authority state and the named
key are absent, and writes an append-only hash-chained journal before creating
the staged key. NCrypt creation uses current-user scope, key spec `0`, and flags
`0`; overwrite and machine-key flags are never used. Durable name arbitration
occurs at finalization.

A successful finalization is followed by P-256 public identity validation, an
NCrypt-sign/BCrypt-verify known-answer test and a versioned root-signing
transaction written before root signing. It binds the operation/provider/key,
serial, exact reference time and validity, public blob/SPKI, authority ID, and
exact DER TBSCertificate/hash. A returned root signature is staged inside the
journal and is adopted only when its TBS and signature validate against that
transaction. Reconciliation never regenerates root parameters and re-signs, if
necessary, only the exact persisted TBS. A journal-local publication record
then binds the authority schema and exact root bytes/hash. Reconciliation
validates pending and final staging deterministically and safely finishes
missing final publication without replacing mismatched bytes. Exactly one
initialization audit is verified before idempotent completed-journal archival;
completed archived operations remain replay-discoverable. An undifferentiated
`E_UNEXPECTED` finalization failure is not called proof of collision. The
operator must preserve the evidence and select a new key name and state
directory.

`--reconcile-intent` requires documented successful-finalization evidence and
reopens and validates that exact key. `--abandon-intent` requires absence of
success or ambiguous-finalization evidence and proves exact key absence. It
deletes nothing.

## Persistent state

The state directory contains:

```text
authority.lock
authority.json
root.der
init-intents\active\
init-intents\archive\completed\
init-intents\archive\abandoned\
issuances\
abandoned-issuances\
serial-reservations\
idempotency\
audit\
```

JSON schemas are versioned and reject unknown fields and trailing data. Files
are published with deterministic create-new staging, flush, close, reopen, validation,
non-replacing rename, final reopen, and parent flush where supported. State
paths must be absolute and local and may not contain reparses, relative
components, device syntax, UNC syntax, or alternate data streams.
The state root, every state subdirectory, lock, staging file, and durable file
are created atomically with a protected security descriptor granting full
control only to the current user and SYSTEM; objects are never created
permissively and hardened afterward. Owner, DACL protection, trustees, rights,
inheritance flags, and every existing state-tree entry are validated before
online or offline use.

Each certificate receives a random positive 128-bit serial reserved before
signing and never reused. The issuance directory and durable intent establish
the operation, idempotency, and serial binding before the separate reservation
is published. Empty, intent-only, signed pre-commit, and legacy orphan
reservation states fail closed and remain reachable through
`quarantine-issuance`; quarantined intent serials are never reused. Intent,
certificate, record, completion marker,
idempotency mapping, and accepted audit are bound by a durable commit record.
Intent and serial-reservation `.pending` files are excluded from finalized
enumeration but scanned explicitly. Exact canonical transaction bytes are
completed; empty, mismatched, or otherwise unresolved evidence fails closed
and can be preserved by quarantine without permitting a second signing.
Startup and replay finish missing post-commit publications byte-for-byte;
pre-commit or inconsistent state fails closed and never causes a second
certificate to be issued. An incomplete issuance blocks startup. The offline
quarantine command preserves its bytes and reservation under
`abandoned-issuances`; a completed quarantine does not block startup.

## Certificate requests and profiles

Enrollment accepts only complete canonical DER PKCS#10 with:

* version `0`;
* parameterless ECDSA-SHA256 signature;
* uncompressed P-256 subject public key;
* valid proof of possession through BCrypt and Crypt32;
* exactly one `extensionRequest`;
* exactly one SAN extension containing one through sixteen DNS/IP entries;
* the exact critical `digitalSignature` request emitted by the documented
  `certreq` INF may also be present and is rebuilt rather than copied.

The bounded CSR subject is parsed but ignored. Unsupported extensions, SAN
types, duplicate SANs, wildcard names, Unicode DNS, and nonallowlisted SANs are
rejected. The issued leaf has an empty subject, critical exact SAN, critical
`CA=false`, critical `digitalSignature`, server-auth EKU, SKI, and root AKI.
The root is `CN=AziHSM Demo Root`, `CA=true`, path length zero, and
`keyCertSign`.

## HTTP API

The server supports one HTTP/1.1 request per connection and always closes it.
It requires `Content-Length` framing and rejects duplicate headers, transfer
encoding, chunking, trailers, upgrade, unsupported expectation, ambiguous
targets, surplus bytes, and pipelining.
Readiness starts false. The recursive watch is registered before the first
state-validating scan; notifications captured before or during that scan are
drained using the same replacement/rescan loop before readiness can become
true. One absolute ten-second deadline starts when a socket is accepted, remains
attached while it waits in the bounded queue, and covers header reads, body
reads, response writes, and flushes. Expired queued sockets are dropped and
release their admission permits. A recursive `ReadDirectoryChangesW` watcher
makes state-dependent routes unavailable while changes are validated under the
issuance mutex. Watcher failure or overflow installs a replacement watch before
scanning. Notifications captured during the scan are consumed; changes or
further overflows repeat replacement/scan processing until a watched,
quiescent scan succeeds. Recurring scans include a named-key KAT. `/livez`
remains process-only.

Routes are:

* `GET /livez`
* `GET /readyz`
* `GET /v1/ca`
* `GET /v1/ca/root`
* `POST /v1/certificates`
* `GET /v1/certificates/{id}`
* `GET /v1/certificates/{id}/status`

Enrollment requires `Content-Type: application/pkcs10` and one lowercase
32-hex `Idempotency-Key`. The first accepted request returns `201`; an exact
replay returns `200` with byte-identical DER; a changed request under the same
key returns `409`. Metadata links are fixed relative paths and never reflect
`Host`.

Status reports only the currently loaded record and stored expiry. It is not a
revocation or general-validity assertion. Unknown, malformed, incomplete, and
quarantined identifiers use the same `404` shape.

## Windows PowerShell 5.1 enrollment

Generate DER directly with `certreq.exe -new -f -q -binary`. Do not transcode
DER through text and do not combine `Invoke-WebRequest -OutFile` with
`-PassThru`. Persist raw response bytes:

```powershell
function Write-RawWebResponseBody {
    param(
        [Parameter(Mandatory = $true)] $Response,
        [Parameter(Mandatory = $true)] [string] $LiteralPath
    )

    if ($Response.Content -is [byte[]]) {
        [System.IO.File]::WriteAllBytes(
            [System.IO.Path]::GetFullPath($LiteralPath),
            [byte[]]$Response.Content)
        return
    }
    if ($null -ne $Response.RawContentStream) {
        if ($Response.RawContentStream.CanSeek) {
            $Response.RawContentStream.Position = 0
        }
        $Output = [System.IO.File]::Open(
            [System.IO.Path]::GetFullPath($LiteralPath),
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        try {
            $Response.RawContentStream.CopyTo($Output)
            $Output.Flush()
        }
        finally {
            $Output.Dispose()
        }
        return
    }
    throw 'BLOCKED: response exposed only decoded text'
}
```

IIS `WebAdministration` setup must run from Windows PowerShell 5.1. Trust the
independently hashed `root.der` out of band; the CA does not mutate trust.

## Standalone acceptance harness

Prebuild and discover the integration-test executable:

```powershell
cargo test --locked -p azihsm-ca --test windows_acceptance `
    --target x86_64-pc-windows-msvc --no-run --message-format=json
```

Copy that executable as `windows_acceptance.exe` together with `root.der`, the
CSR, certificate, and an authenticated hash manifest. On the TLS-server VM set
absolute `AZIHSM_ACCEPTANCE_ROOT_DER`, `AZIHSM_ACCEPTANCE_CSR_DER`,
`AZIHSM_ACCEPTANCE_CERT_DER`, `AZIHSM_ACCEPTANCE_ROOT_SHA256`,
`AZIHSM_ACCEPTANCE_ROOT_SPKI_SHA256`, `AZIHSM_ACCEPTANCE_DNS`, and
`AZIHSM_ACCEPTANCE_IP`, then run:

```powershell
.\windows_acceptance.exe --ignored --exact `
    validate_cross_vm_enrollment_artifacts --nocapture
```

Run bounded packet captures separately: enrollment traffic on the TLS-server
VM around the first port `8080` POST, and TLS traffic on the client VM around
one port `8443` HTTPS request. Evidence supports only traffic observed in each
recorded interval.

## Limitations

This release is Windows-only, single-authority, single-process, plain HTTP,
server-auth-only, and intended for a controlled demonstration network. It has
no HA, rotation, renewal automation, revocation, client enrollment,
authentication, API encryption, or automatic key adoption, recreation,
overwrite, deletion, or repair.
