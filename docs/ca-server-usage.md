# AziHSM CA Server Operator Guide

This guide runs the Windows-only `azihsm-ca` demonstration server for a
one-way TLS scenario. It is demo guidance, not production deployment advice.
For implementation details and the full state model, see the
[crate README](../crates/azihsm-ca/README.md).

## Security and cryptographic boundary

The CA is a persistent, named-key ECDSA P-256 authority:

* CA key creation, persistence, opening, and every root or leaf signature use
  Windows NCrypt with the registered
  `Microsoft Azure Integrated HSM Key Storage Provider`.
* CA private-key bytes are never exported. There is no software CA-signing
  fallback.
* The operator CLI does not provide a general CA-key deletion command. Any
  implementation-owned test cleanup deletion also uses NCrypt.
* Rust libraries parse and verify CSRs, build X.509 structures, hash public
  data, and generate identifiers. They do not possess the CA private key.

Do not confuse the two keys in the demo:

* The **TLS server private key** is generated on the TLS-server machine and
  stays associated with its PKCS #10 CSR and issued leaf certificate.
* The **CA private key** is a named, current-Windows-user AziHSM KSP key on the
  CA machine. It signs the root and the TLS server certificate and never
  leaves the provider.

In one-way TLS, the TLS server enrolls for a certificate. The TLS client does
not enroll; it installs the CA root as a trust anchor and validates the server
certificate locally.

## Prerequisites

* Windows with the current AziHSM KSP installed and registered under the exact
  provider name shown above.
* Rust `1.88` or newer and the `x86_64-pc-windows-msvc` target.
* The CA process must run as the same Windows user that initialized the named
  key. Named-key access is current-user scoped.
* A local, absolute state path such as `C:\azihsm-demo\ca-state`.
    * Do not use relative paths, `.` or `..`, UNC paths, device paths,
      alternate data streams, network shares, or reparse-point paths.
    * Prefer a new path that does not yet exist. Let `azihsm-ca` create and
      protect it for the current user and `SYSTEM`.
* Network reachability from the TLS server to the selected CA listen address
  and port. A non-loopback demo requires an explicit insecure-HTTP flag and an
  appropriate Windows Firewall rule.
* `certreq.exe` for the PowerShell enrollment example.

Run build commands from the repository root. Run the executable from any
working directory, but always pass an absolute `--state-dir`. The examples
below keep generated demo artifacts in a separate local working directory.

## Build

From the repository root in PowerShell:

```powershell
cargo build --locked `
    --manifest-path .\crates\Cargo.toml `
    -p azihsm-ca `
    --target x86_64-pc-windows-msvc `
    --release

$CaExe = (Resolve-Path `
    .\crates\target\x86_64-pc-windows-msvc\release\azihsm-ca.exe).Path
```

Discover the current CLI contract instead of relying on remembered syntax:

```powershell
& $CaExe --help
& $CaExe init --help
& $CaExe serve --help
& $CaExe inspect --help
& $CaExe quarantine-issuance --help
```

## CLI reference

### `init`

Create a new authority:

```text
azihsm-ca init --state-dir PATH
  --provider "Microsoft Azure Integrated HSM Key Storage Provider"
  --key-name NAME
  [--root-valid-days 3650]
```

* `--state-dir` must be an absolute local path.
* `--key-name` must contain 1-128 ASCII letters, digits, `.`, `_`, or `-`.
* `--root-valid-days` defaults to `3650` and permits `30` through `3650`.
* The provider value must match exactly.

Initialization recovery modes are mutually exclusive with fresh creation:

```text
azihsm-ca init --state-dir PATH --reconcile-intent LOWERCASE_HEX32
azihsm-ca init --state-dir PATH --abandon-intent LOWERCASE_HEX32
```

### `serve`

```text
azihsm-ca serve --state-dir PATH
  [--listen 127.0.0.1:8080]
  [--allow-dns LOWERCASE_DNS]...
  [--allow-ip ADDRESS]...
  [--leaf-validity-days 1]
  [--max-connections 16]
  [--allow-insecure-demo-http-nonloopback]
```

* At least one `--allow-dns` or `--allow-ip` is required.
* Repeat either flag to allow multiple exact SANs.
* DNS values are exact, lowercase ASCII LDH names. Wildcards, suffix matching,
  uppercase names, Unicode names, and a trailing dot are not accepted.
* IP values must parse as IPv4 or IPv6 addresses. Authorization compares the
  parsed address values exactly; unspecified and multicast addresses are
  rejected.
* `--leaf-validity-days` permits `1` through `7`; the certificate is also
  capped by the root's expiry.
* `--max-connections` permits `1` through `64`.
* Unspecified and multicast listen addresses are forbidden.
* Any non-loopback listen address requires
  `--allow-insecure-demo-http-nonloopback`.

### Offline inspection and recovery

```text
azihsm-ca inspect --state-dir PATH
azihsm-ca quarantine-issuance --state-dir PATH --issuance-id LOWERCASE_HEX32
```

`inspect` validates the state tree, root, named key, journals, completed
issuances, reservations, idempotency records, and audit chain. On success it
prints JSON containing the authority and root identifiers, object counts, and
`"ready": true`.

The process exit codes are:

| Code | Meaning |
|---:|---|
| `0` | Success |
| `2` | CLI usage |
| `3` | State |
| `4` | Provider or key |
| `5` | Pending initialization recovery |
| `6` | Identity, profile, or cryptographic validation |
| `7` | HTTP runtime |
| `8` | Issuance or durability |
| `9` | Reserved; not emitted |
| `10` | Already initialized |
| `11` | State busy |
| `12` | Recovery or quarantine refused |

## Initialize a new authority

Use a new state path and a collision-resistant named key. Normal startup never
creates or replaces an authority: `serve` only loads the persisted state,
opens the exact recorded named key, checks its identity, and fails closed if
anything does not match.

```powershell
$DemoDir = Join-Path $PWD.Path 'demo-output'
New-Item -ItemType Directory -Force -Path $DemoDir | Out-Null

# Do not pre-create this state directory.
$StateDir = Join-Path $DemoDir 'ca-state'
$KeyName = 'azihsm-demo-' + [Guid]::NewGuid().ToString('N')

& $CaExe init `
    --state-dir $StateDir `
    --provider 'Microsoft Azure Integrated HSM Key Storage Provider' `
    --key-name $KeyName `
    --root-valid-days 365

if ($LASTEXITCODE -ne 0) {
    throw "CA initialization failed with exit code $LASTEXITCODE"
}

& $CaExe inspect --state-dir $StateDir
```

Initialization is not an idempotent "ensure exists" operation. Do not rerun
fresh `init` against populated state. This implementation accepts only fresh
state format `1`, producer `azihsm-ca-rcgen-actix-v1`; it does not migrate or
adopt older state.

If an older named key may still exist, choose both a new state directory and a
new unique key name. Never use overwrite to reuse a name: replacing a named
key can split authority identity between old handles and the new backing key.

## Start the HTTP service

For a loopback-only check:

```powershell
& $CaExe serve `
    --state-dir $StateDir `
    --listen '127.0.0.1:8080' `
    --allow-dns 'server.demo.internal' `
    --allow-ip '192.0.2.20'
```

For a private demo network, bind a specific CA interface address rather than
`0.0.0.0`:

```powershell
& $CaExe serve `
    --state-dir $StateDir `
    --listen '192.0.2.10:8080' `
    --allow-dns 'server.demo.internal' `
    --allow-ip '192.0.2.20' `
    --leaf-validity-days 1 `
    --max-connections 16 `
    --allow-insecure-demo-http-nonloopback
```

The process prints the accepted-risk warning to standard error. It does not
print a separate "ready" banner. Readiness begins false while the state,
named-key identity, root, journals, and issuance records are checked. Poll
`/readyz`; do not treat a listening socket or `/livez` as readiness.

```powershell
$CaBase = 'http://192.0.2.10:8080'
Invoke-RestMethod "$CaBase/livez"

do {
    try {
        $Ready = Invoke-RestMethod "$CaBase/readyz"
    }
    catch {
        Start-Sleep -Milliseconds 250
        $Ready = $null
    }
} until ($Ready.ready -eq $true)
```

The service uses plain HTTP/1.1, disables keep-alive, and closes each
connection. Requests have an accept-time absolute ten-second lifetime.

## HTTP API

Successful JSON and error bodies use schema version `1`. Errors have this
shape:

```json
{
  "schema_version": 1,
  "error": {
    "code": "ca_not_ready",
    "message": "request rejected"
  }
}
```

| Method and route | Success | Media type and response |
|---|---:|---|
| `GET /livez` | `200` | `application/json`: `{"schema_version":1,"live":true}` |
| `GET /readyz` | `200` | `application/json`: `{"schema_version":1,"ready":true}` |
| `GET /v1/ca` | `200` | `application/json`: metadata described below |
| `GET /v1/ca/root` | `200` | `application/pkix-cert`: DER root |
| `POST /v1/certificates` | `201` or `200` | `application/pkix-cert`: DER leaf |
| `GET /v1/certificates/{id}` | `200` | `application/pkix-cert`: stored DER leaf |
| `GET /v1/certificates/{id}/status` | `200` | `application/json`: stored issuance status |

Metadata is:

```json
{
  "schema_version": 1,
  "authority_id": "lowercase-hex-authority-id",
  "root": "/v1/ca/root",
  "certificates": "/v1/certificates"
}
```

Status contains `authority_id`, `issuance_id`, `serial`,
`certificate_sha256`, `not_before`, `not_after`, `state` (`issued` or
`expired`), `revocation_supported: false`, and
`assertion: "recorded_as_issued_by_this_authority"`. It is an issuance record,
not a revocation or complete current-validity assertion.

The root directly signs each leaf, so the demo chain consists of the issued
leaf plus this one root. There is no separate chain-bundle endpoint. A TLS
server normally presents the leaf; the client independently trusts the root.

Every response sends `Connection: close`. A successful enrollment also sends
`X-AziHSM-Issuance-Id` with the lowercase 32-hex issuance identifier. For a
known route, any method other than the one listed above returns `405`. Unknown
`GET` and `POST` routes return the same `404 certificate_not_found` error as
an unknown certificate; other methods on unknown routes return `405`.

Important error statuses are:

| Status | Typical meaning |
|---:|---|
| `400` | Malformed HTTP/CSR body or invalid/missing idempotency key |
| `403` | A requested SAN is not exactly allowlisted |
| `404` | Unknown, malformed, incomplete, or quarantined issuance ID |
| `405` | Method is not allowed |
| `408` or `503` | Request deadline expired |
| `409` | Idempotency key reused for a different request |
| `413` | Request body exceeds 16,384 bytes |
| `415` | Content type is not exactly `application/pkcs10` |
| `422` | Unsupported CSR profile |
| `429` | Per-source or global enrollment rate limit reached |
| `503` | CA unready, work queue busy, or issuance failed closed |

When unready, `/livez` remains `200`, while `/readyz` and state-dependent
routes return `503` with `ca_not_ready`.

## One-way TLS enrollment

### 1. Generate the TLS server key and CSR

The following repository-tested profile generates an ECDSA P-256 key and
binary PKCS #10 CSR for one DNS SAN. Run it on the TLS-server machine under
the account or certificate-store context that will use the private key.

```powershell
$TlsDir = Join-Path $PWD.Path 'tls-server'
New-Item -ItemType Directory -Force -Path $TlsDir | Out-Null
$Inf = Join-Path $TlsDir 'server.inf'
$Csr = Join-Path $TlsDir 'server.csr.der'

@'
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject="CN=server.demo.internal"
Exportable=FALSE
MachineKeySet=FALSE
ProviderName="Microsoft Software Key Storage Provider"
KeyAlgorithm=ECDSA_P256
KeySpec=0
HashAlgorithm=SHA256
RequestType=PKCS10
SuppressDefaults=TRUE
SMIME=FALSE

[Extensions]
2.5.29.17="{text}"
_continue_="DNS=server.demo.internal"
'@ | Set-Content -LiteralPath $Inf -Encoding Ascii

certreq.exe -new -f -q -binary $Inf $Csr
if ($LASTEXITCODE -ne 0) {
    throw "certreq CSR generation failed with exit code $LASTEXITCODE"
}
```

The CA accepts complete DER PKCS #10 only: ECDSA P-256/SHA-256, valid proof of
possession, exactly one `extensionRequest`, and exactly one SAN extension with
1-16 unique DNS/IP entries. Other requested extensions and SAN types are
rejected. The CSR subject is ignored; authorization is based on exact SANs.

If the TLS service requires a machine-store private key, adapt the INF and run
context for that service before generating the CSR. Certificate-store
placement and service-account private-key permissions are deployment-specific;
do not move or export the key merely to satisfy the demo.

### 2. Submit the DER CSR

Enrollment requires:

* `Content-Type: application/pkcs10`
* `Idempotency-Key: ` followed by exactly 32 lowercase hexadecimal digits
* The raw DER CSR as the request body

This helper preserves binary response bytes in Windows PowerShell 5.1:

```powershell
function Write-RawWebResponseBody {
    param(
        [Parameter(Mandatory = $true)] $Response,
        [Parameter(Mandatory = $true)] [string] $LiteralPath
    )

    if ($Response.Content -is [byte[]]) {
        [IO.File]::WriteAllBytes(
            [IO.Path]::GetFullPath($LiteralPath),
            [byte[]]$Response.Content)
        return
    }

    if ($null -ne $Response.RawContentStream) {
        if ($Response.RawContentStream.CanSeek) {
            $Response.RawContentStream.Position = 0
        }
        $Output = [IO.File]::Open(
            [IO.Path]::GetFullPath($LiteralPath),
            [IO.FileMode]::Create,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $Response.RawContentStream.CopyTo($Output)
            $Output.Flush()
        }
        finally {
            $Output.Dispose()
        }
        return
    }

    throw 'Response exposed only decoded text; certificate was not saved'
}

$IdempotencyKey = ([Guid]::NewGuid().ToString('N')).ToLowerInvariant()
$Headers = @{ 'Idempotency-Key' = $IdempotencyKey }
$Leaf = Join-Path $TlsDir 'server.cer'

$Response = Invoke-WebRequest `
    -Uri "$CaBase/v1/certificates" `
    -Method Post `
    -ContentType 'application/pkcs10' `
    -Headers $Headers `
    -InFile $Csr

Write-RawWebResponseBody -Response $Response -LiteralPath $Leaf
$IssuanceId = [string]$Response.Headers['X-AziHSM-Issuance-Id']
```

Do not pipe DER through text cmdlets. In Windows PowerShell 5.1, do not combine
`Invoke-WebRequest -OutFile` with `-PassThru`.

The first accepted request returns `201` and an
`X-AziHSM-Issuance-Id` header. Retrying the byte-identical CSR with the same
idempotency key returns `200`, the same issuance ID, and byte-identical DER,
including after restart. Reusing that key for a different CSR returns `409`.

### 3. Save the root and verify the record

```powershell
$Root = Join-Path $TlsDir 'azihsm-demo-root.cer'
Invoke-WebRequest -Uri "$CaBase/v1/ca/root" -OutFile $Root

$Status = Invoke-RestMethod `
    -Uri "$CaBase/v1/certificates/$IssuanceId/status"
$Status

$StoredLeaf = Join-Path $TlsDir 'server-from-status.cer'
Invoke-WebRequest `
    -Uri "$CaBase/v1/certificates/$IssuanceId" `
    -OutFile $StoredLeaf
```

Authenticate the root's hash through an independent channel before trusting
it. Fetching a root over this same unauthenticated plain-HTTP connection is not
proof that it is the intended trust anchor.

### 4. Install and use the certificates

On the TLS-server machine, associate the issued leaf with the private key
created for the CSR. When the request was created in the intended Windows
certificate-store context, the usual starting point is:

```powershell
certreq.exe -accept $Leaf
```

Store selection, service binding, and private-key ACLs vary by TLS server. For
example, a Windows service commonly needs a machine-store request and explicit
permission for its service identity. Treat those values as deployment
placeholders and verify that the installed leaf reports an associated private
key before binding it.

On the TLS-client machine, after independently verifying the root hash, import
the root into the trust store used by that client. An administrator can use:

```powershell
Import-Certificate `
    -FilePath $Root `
    -CertStoreLocation 'Cert:\LocalMachine\Root'
```

Configure the TLS server to present the issued leaf. Because the leaf is
directly signed by the root, there is no intermediate certificate to serve.
Connect using a DNS name or IP address present in the leaf SAN.

## Persistence, readiness, and recovery

### Normal restart

Stop the process and rerun the same `serve` command with the same state
directory and Windows user. The server reopens the recorded named key and
revalidates durable state. Issuance records and idempotency mappings persist,
so an exact replay remains byte-identical.

### Runtime fail-closed behavior

A recursive state watcher makes readiness false before revalidation whenever
state changes. Missing, malformed, incomplete, mismatched, rolled-back, or
unexpected state keeps state-dependent routes at `503`. The named key is also
rechecked. `/livez` only proves that the process is running.

Do not repair JSON, DER, marker, journal, reservation, idempotency, or audit
files by hand.

### Initialization recovery

An interrupted initialization leaves an operation ID under
`init-intents\active`. Use:

```powershell
Get-ChildItem -LiteralPath (Join-Path $StateDir 'init-intents\active')
```

Then choose only the procedure justified by the preserved journal evidence:

* `--reconcile-intent ID` requires documented successful key finalization. It
  reopens and validates that exact key and completes the persisted
  transaction.
* `--abandon-intent ID` requires absence of successful or ambiguous
  finalization evidence and proof that the exact key is absent. It deletes
  nothing.
* If finalization failed ambiguously, including an undifferentiated
  `E_UNEXPECTED`, preserve the state and use a new state path and key name.
  Do not assume collision, overwrite, delete, reconcile, or abandon.

### Incomplete issuance recovery

Startup normally completes safe post-commit publication byte-for-byte. An
incomplete or inconsistent pre-commit issuance blocks readiness to avoid a
second CA signature. After preserving and reviewing the evidence, quarantine
that exact lowercase 32-hex issuance ID offline:

```powershell
& $CaExe quarantine-issuance `
    --state-dir $StateDir `
    --issuance-id '0123456789abcdef0123456789abcdef'
```

Quarantine moves the evidence under `abandoned-issuances`, keeps any serial
reserved, writes an audit record, and permits a later clean startup. It refuses
completed issuances, cross-authority evidence, and inconsistent references.

## Troubleshooting

### The server is live but unready

* Confirm `/livez` is `200` and `/readyz` is `503`.
* Stop the server and run `inspect`.
* Check that the same Windows user is running the process and can access the
  registered provider and named key.
* Look for an active initialization intent or incomplete issuance.
* Use only the documented reconcile, abandon, or quarantine command whose
  preconditions are satisfied.

### SAN authorization returns `403`

Ensure every CSR DNS/IP SAN exactly matches a repeated `--allow-dns` or
`--allow-ip` value. DNS comparison is lowercase and exact; there are no
wildcards, suffixes, CN fallback, or case folding.

### CSR returns `400` or `422`

* Send raw DER, not PEM, Base64, JSON, form data, or decoded text.
* Keep the body at or below 16,384 bytes.
* Use P-256 with parameterless ECDSA-SHA256 and a valid CSR signature.
* Request exactly one SAN extension containing 1-16 unique supported DNS/IP
  names and no other extensions.
* `400 malformed_csr` indicates malformed DER/signature structure.
* `422 unsupported_csr_profile` indicates a well-formed but unsupported
  request profile.

### Enrollment returns `415`

Set `Content-Type` exactly to `application/pkcs10`; parameters such as
`; charset=utf-8` are not accepted.

### State marker or schema is rejected

The current marker must identify format `1` and producer
`azihsm-ca-rcgen-actix-v1`. Older or manually altered state is not migrated.
Preserve it and initialize a new state path with a new unique key name.

### Initialization reports an existing or ambiguous named key

Do not overwrite the key. Preserve the failed state and choose both a fresh
state path and a fresh collision-resistant name.

### Requests return `429`, `408`, or `503 busy`

Enrollment starts with a burst of three requests per source, refilling one
request every six seconds. The global burst is ten, refilling one per second.
Work queues are bounded, and each connection has a ten-second absolute
lifetime. Back off and retry the same CSR with the same idempotency key.

### Clients cannot connect

* Verify the service used the intended specific `--listen` address and port.
* Verify the non-loopback acknowledgement flag was supplied.
* Confirm `/livez` locally on the CA host.
* Add a narrowly scoped inbound Windows Firewall rule for the demo network.
* Confirm routing and that no other process owns the port.

## Demonstration limitations

This implementation intentionally has the following limitations:

* Enrollment is unauthenticated. Any reachable caller can obtain a certificate
  for an allowlisted SAN using its own key.
* The CA API is plain HTTP, with no confidentiality, integrity, or endpoint
  authentication.
* Any process running as the CA Windows user can reopen and use the named key,
  bypassing API policy, records, limits, and audit.
* The CA user can coherently roll back, replace, or delete local state without
  reliable detection; status and audit may be incomplete or inaccurate.
* There is no revocation, CRL, or OCSP service. Certificates may remain usable
  until expiry or removal of trust.
* The server is single-authority, single-process, and server-auth-only. It has
  no HA, automated renewal, rotation, client enrollment, or mTLS workflow.

Use this only on a controlled demonstration network.
