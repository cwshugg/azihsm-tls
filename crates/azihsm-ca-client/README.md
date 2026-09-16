# `azihsm-ca-client`

`azihsm-ca-client` is the neutral library shared by the standalone
`azihsm-ca-demo` and `azihsm-tls-server` applications. It provides the bounded
plain-HTTP CA protocol, exact DTOs and failure classification, configurable
public-data transcripts, input validation, P-256 CSR construction, and exact
certificate-profile verification. It also owns the identical reparse-safe
public artifact, deletion-intent, and `.azihsm-state.lock` primitives used by
both applications.

It contains no application CLI, TLS certificate cache, renewal retention, or
TLS runtime. Persistent AziHSM key lifecycle and signing remain in
`azihsm-ncrypt`.
