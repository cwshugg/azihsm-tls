# AziHSM CA Enrollment Demo

`azihsm-ca-demo` is a Windows-only Rust CLI for creating a named,
current-user ECDSA P-256 TLS key through the AziHSM NCrypt provider and
enrolling it with this repository's demonstration CA.

The executable remains independent from `azihsm-tls-server`. Both applications
reuse the neutral `azihsm-ca-client` protocol library and `azihsm-ncrypt` key
library, but do not depend on each other or share application state.

The private key remains non-exportable in AziHSM. The CLI publishes only
public artifacts and prints a default-on HTTP/local metadata transcript;
private-key bytes and handles are never exported or printed. RSA generation
is unsupported.

For prerequisites, complete command documentation, artifact descriptions,
wire transcript examples, retry and deletion behavior, verification rules,
and demo risks, see the
[AziHSM CA enrollment demo guide](../../docs/azihsm-ca-demo.md).

```powershell
cargo build --locked `
    --manifest-path .\crates\Cargo.toml `
    -p azihsm-ca-demo `
    --release `
    --target x86_64-pc-windows-msvc

.\crates\target\x86_64-pc-windows-msvc\release\azihsm-ca-demo.exe create `
    --output-dir C:\azihsm-demo\tls-server `
    --subject-cn server.demo `
    --dns server.demo `
    --ca-url http://127.0.0.1:8080 `
    --acknowledge-plain-http
```
