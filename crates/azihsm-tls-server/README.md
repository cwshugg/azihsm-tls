# `azihsm-tls-server`

`azihsm-tls-server` is a Windows-only TLS 1.3 framed echo server. Its
persistent ECDSA P-256 private key remains non-exportable in the current-user
AziHSM KSP. It reuses neutral CA protocol, transcript, CSR, and verification
primitives and the cross-application state lock from `azihsm-ca-client`, while
owning its cache, renewal, deletion, and TLS runtime. It does not depend on
`azihsm-ca-demo`.

Operational tracing preserves stable `event` fields and adds concise human
`message` descriptions. CA and framed-message payload transcripts remain
separate, complete, and default-on.

The server supports `run`, `show`, and `delete-key`. See the complete
[AziHSM TLS server guide](../../docs/azihsm-tls-server.md) for prerequisites,
CA setup, trust, framing, testing, logging, renewal, and cleanup.
