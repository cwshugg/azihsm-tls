# AziHSM CA Enrollment Demo Guide

This guide operates the Windows-only `azihsm-ca-demo` client against the
repository's demonstration CA. For CA setup and API details, see the
[CA server operator guide](ca-server-usage.md).

The client creates a current-user named TLS key through
`Microsoft Azure Integrated HSM Key Storage Provider`, signs a PKCS #10
certificate signing request through NCrypt, enrolls it, verifies the returned
certificate chain, and publishes public artifacts. Private-key bytes and
native handles are never exported, available to the process, written, or
printed.

## Prerequisites

* Windows with the AziHSM KSP installed and registered.
* Rust 1.88 or newer with the `x86_64-pc-windows-msvc` target.
* A running `azihsm-ca` server whose exact SAN allowlist includes every DNS
  name and IP address requested by the client.
* An absolute local output path whose parent exists.
* Network access to the CA's explicit `http://` origin.

This workflow supports only ECDSA P-256 keys and SHA-256 signatures. RSA key
generation is not offered because the validated provider path and CA profile
for this repository are specifically P-256/SHA-256; there is no demonstrated
RSA generation contract to fall back to safely.

## Build

Run from the repository root:

```powershell
cargo build --locked `
    --manifest-path .\crates\Cargo.toml `
    -p azihsm-ca-demo `
    --release `
    --target x86_64-pc-windows-msvc

$DemoExe = (Resolve-Path `
    .\crates\target\x86_64-pc-windows-msvc\release\azihsm-ca-demo.exe).Path
```

Inspect the installed command contract:

```powershell
& $DemoExe --help
& $DemoExe create --help
& $DemoExe retry --help
& $DemoExe show --help
& $DemoExe delete-key --help
```

## Create

`create` performs the complete key, CSR, readiness, enrollment, verification,
and publication workflow:

```powershell
$Output = 'C:\azihsm-demo\tls-server'

& $DemoExe create `
    --output-dir $Output `
    --subject-cn 'server.demo' `
    --dns 'server.demo' `
    --ip '192.0.2.20' `
    --ca-url 'http://192.0.2.10:8080' `
    --acknowledge-plain-http
```

Flags:

* `--output-dir PATH` is required. The path must be absolute, local, free of
  reparse points, and new or empty.
* `--subject-cn TEXT` is required and accepts 1-128 non-control characters.
* `--dns NAME` is repeatable.
* `--ip ADDRESS` is repeatable.
* At least one DNS or IP SAN is required; at most 16 total are accepted.
  Values must be unique. DNS names must be lowercase ASCII LDH names without
  wildcards or a trailing dot. Unspecified and multicast IPs are rejected.
* `--ca-url URL` is required and must be an `http://` origin without
  credentials, query, fragment, or additional path.
* `--acknowledge-plain-http` is required.
* `--key-name NAME` is optional. The default is a collision-resistant
  `azihsm-tls-<hex>` name. A supplied name must contain 1-128 ASCII letters,
  digits, `.`, `_`, or `-`.

The key is current-user scoped. Creation uses no machine-key or overwrite
flag. Before finalization, recoverable metadata and a finalize-started marker
are durably published. If interruption occurs before request metadata is
complete, rerun the exact `create` command. It reopens only a marker-associated
key and reuses an already-published CSR. An ambiguous failed finalization is
recorded and requires a new output directory and key name.

## Retry

```powershell
& $DemoExe retry `
    --output-dir $Output `
    --acknowledge-plain-http
```

`retry` reads immutable request metadata, opens the same named key, compares
its exported public SPKI with the stored identity, validates the original CSR
and proof of possession, and sends that byte-identical CSR with the same
lowercase 32-hex idempotency key. It never generates a replacement key, CSR,
or idempotency key.

The first successful enrollment returns HTTP `201`; an idempotent replay
returns `200` with the same issuance ID and leaf bytes.

## Show

```powershell
& $DemoExe show --output-dir $Output
```

`show` prints public operational fields: provider, key name, scope, algorithm,
subject CN, SANs, CSR/SPKI hashes, authority and issuance IDs, certificate
hashes, verification time, and deletion status. It does not open or print a
private key.

## Delete the Key

Copy the exact key name from `show`:

```powershell
$KeyName = '<exact key name>'

& $DemoExe delete-key `
    --output-dir $Output `
    --confirm-key-name $KeyName
```

Deletion fails unless the confirmation matches immutable metadata. Before
deletion, the command opens the named key and verifies that its exported SPKI
is byte-identical to `public-key.der` and its recorded SHA-256. It atomically
writes `deletion-intent.json` before calling NCrypt deletion, then deletes that
exact key, verifies absence, and atomically writes `deletion-record.json`.
Re-run the same command after an interruption: a valid identity-bound intent
allows it to finish deletion or publish the final record when the key is
already absent. Absence without a valid intent is rejected. `show` reports
`pending recovery` or `completed` without claiming an unproven deletion.
Public certificates and evidence remain.

## Output Artifacts

The output directory contains:

| Artifact | Contents |
|---|---|
| `request-metadata.json` | Provider/key reference, algorithm, scope, subject, SANs, CA URL, idempotency key, hashes, and filenames |
| `public-key.der`, `public-key.pem` | P-256 SubjectPublicKeyInfo |
| `request.csr.der`, `request.csr.pem` | Exact NCrypt-signed PKCS #10 request |
| `root.der`, `root.pem` | Verified CA root |
| `leaf.der`, `leaf.pem` | Verified issued TLS-server certificate |
| `chain.pem` | Leaf followed by directly signing root |
| `issuance-metadata.json` | Authority/issuance IDs, response status, hashes, verification time, and filenames |
| `deletion-intent.json` | Optional durable provider/key/SPKI identity and confirmed deletion operation |
| `deletion-record.json` | Optional confirmed deletion evidence |

Publication uses same-directory create-new staging, file flush, reopen and
byte comparison, non-replacing rename, and best-effort Windows directory
flush. Existing conflicting bytes are never overwritten.

No file contains private-key bytes.

## Wire Transcript

The transcript is deterministic and enabled by default. It is separate from
operational tracing and remains visible when `RUST_LOG=off`.

For each exchange it prints:

* Direction, HTTP method, exact path, and response status.
* Relevant `Content-Type`, `Accept`, `Idempotency-Key`, and
  `X-AziHSM-Issuance-Id` headers.
* Every complete JSON response, pretty-printed.
* The outbound DER CSR and inbound DER certificates as copyable PEM, with
  exact byte length and SHA-256.
* Local staging, request, issuance, and deletion JSON when read or written.

Binary DER is never written directly to the terminal. The transcript can
contain public key names, subjects, SANs, URLs, idempotency values, CSR/SPKI
material, certificates, hashes, and issuance IDs. Do not treat it as a
secret-free operational log. It never contains private-key bytes or handles.

Example excerpt:

```text
PRIVATE KEY LIMITATION: private key bytes and handles are never exported, available, or printed.
=== HTTP REQUEST ===
Direction: outbound
Method: POST
Path: /v1/certificates
Content-Type: application/pkcs10
Accept: application/pkix-cert
Idempotency-Key: 0123456789abcdef0123456789abcdef
Byte-Length: 245
SHA-256: <csr-sha256>
Body (PEM):
-----BEGIN CERTIFICATE REQUEST-----
<public CSR base64>
-----END CERTIFICATE REQUEST-----
=== END HTTP REQUEST ===
=== HTTP RESPONSE ===
Direction: inbound
Method: POST
Path: /v1/certificates
Status: 201
Content-Type: application/pkix-cert
X-AziHSM-Issuance-Id: 0123456789abcdef0123456789abcdef
Byte-Length: 420
SHA-256: <leaf-sha256>
Body (PEM):
-----BEGIN CERTIFICATE-----
<public certificate base64>
-----END CERTIFICATE-----
=== END HTTP RESPONSE ===
```

## Operational Tracing

Compact timestamp-free tracing is written to standard output at `info` by
default. `RUST_LOG` accepts exactly `off`, `error`, `warn`, `info`, `debug`, or
`trace`. Invalid values exit with code `2`; module filters and comma-separated
directives are unsupported.

Tracing reports bounded lifecycle events. The transcript—not tracing—is the
deliberately verbose record of public request, response, and local metadata.

## Verification

Before publication, the client verifies:

* Root self-signature, current validity, P-256/SHA-256 algorithms, CA basic
  constraints, certificate-signing key usage, and exact extension profile.
* Leaf signature by the fetched root, exact issuer, current validity,
  P-256/SHA-256 algorithms, non-CA constraints, digital-signature usage,
  server-auth EKU, and exact extension profile.
* Exact requested DNS/IP SAN set without wildcard or duplicate values.
* Byte-identical leaf SPKI and named-key-exported SPKI.
* Chain ordering as leaf followed by root.

## Troubleshooting

* `ca_not_ready`: inspect the CA state and poll `/readyz`; see the
  [CA server guide](ca-server-usage.md).
* `san_not_authorized`: `--listen` controls only the CA's network binding; it
  does not authorize certificate names. Restart or reconfigure the CA with one
  exact `--allow-dns` or `--allow-ip` value for every requested SAN. Wildcards
  are unsupported. The demo prints the required values; then reuse the same
  AziHSM key, CSR, and idempotency key:

  ```powershell
  & $DemoExe retry `
      --output-dir $Output `
      --acknowledge-plain-http
  ```
* `unsupported_csr_profile`: preserve the output directory and inspect the
  printed CSR transcript; do not generate a replacement during an uncertain
  retry.
* `idempotency_conflict`: the idempotency key was previously bound to
  different CSR bytes. Preserve all evidence.
* Existing conflicting artifacts: use a new output directory rather than
  overwriting public evidence.
* Named key unavailable: run under the Windows user that created the key and
  verify that the exact provider is registered.

## Demonstration Risks

* Enrollment is unauthenticated; any reachable caller can request an
  allowlisted identity.
* Plain HTTP provides no confidentiality, integrity, or CA endpoint
  authentication.
* The transcript exposes public enrollment metadata and idempotency material.
* Any process running as the same Windows user may be able to use the named
  key through the provider.
* Root retrieval does not establish trust; authenticate the root independently.
* There is no revocation, CRL, OCSP, renewal automation, TLS binding, or trust
  distribution.
