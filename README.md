# AziHSM TLS Proof-of-Concept

[**Azure Integrated HSM**](https://github.com/microsoft/AziHSM-Guest) (**AziHSM**) is a **Hardware Security Module** (**HSM**) that enables the creation, caching, and usage of cryptographic keys within an isolated hardware environment.
Latest Azure VM generations have the option to attach to a local AziHSM device, which can be used to store keys locally and use the AziHSM device's crypto engines to perform crypto operations.

AziHSM supports a variety of customer scenarios.
However, throughout our testing and development, one scenario we haven't visited is using AziHSM to manage keys for a [**Transport Layer Security**](https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/) (**TLS**) server.
This project aims to explore that scenario; this repository contains the files and code from our 2026 hackathon project.

## Project Agenda

The end goal of this project is to demonstrate a three-VM setup, where each VM uses a separate AziHSM device to enable TLS communication:

1. **VM 1** - Implement a basic **Mock CA** (**Certificate Authority**).
    * This Mock CA will use the AziHSM device to issue a mock certificate to our TLS Server.
2. **VM 2** - Implement a basic **TLS Server**.
    * This TLS Server will communicate with the Mock CA to receive a certificate and associate it with its own public/private key pair, with which it enables secure communication with a TLS Client.
3. **VM 3** - Implement a basic **TLS Client**.
    * This TLS Client will reach out to the TLS Server for secure communication.

### Tasks

| **Task** | **Status** | **Description** |
|----------|------------|-----------------|
| Implement Mock CLA | Done | See [`azihsm-ca`](crates/azihsm-ca) |
| Implement TLS Server | TODO | |
| Test TLS-Server-to-Mock-CLA certificate issuing | TODO |
| Implement TLS Client | TODO | |
| Test TLS-Client-to-TLS-Server communication | TODO | |
| Test full workflow | TODO | |
| Record demonstration of full workflow | TODO | |

## Rust Crates

This repo contains multiple Rust crates:

* [`azihsm-ca`](crates/azihsm-ca) - A mock CA (Certificate Authority) server.
* [`azihsm-ca-demo`](crates/azihsm-ca-demo) - A sample application demonstrating how a client would communicate with the mock CA server (`azihsm-ca`).
* [`azihsm-ncrypt`](crates/azihsm-ncrypt) - A helper crate implementing shared code to interact with the AziHSM KSP in Windows.

## Quick Start

On Windows with Rust 1.88+ and the AziHSM KSP, build both required binaries:

```powershell
cargo build --locked --manifest-path .\crates\Cargo.toml `
    -p azihsm-ca -p azihsm-ca-demo `
    --release --target x86_64-pc-windows-msvc
```

Initialize and serve the demo-only plain-HTTP CA using the
[`azihsm-ca` operator guide](docs/ca-server-usage.md), then enroll with the
[`azihsm-ca-demo` guide](docs/azihsm-ca-demo.md):

```powershell
New-Item -ItemType Directory -Force C:\azihsm-demo | Out-Null
.\crates\target\x86_64-pc-windows-msvc\release\azihsm-ca.exe init `
    --state-dir C:\azihsm-demo\ca-state `
    --provider 'Microsoft Azure Integrated HSM Key Storage Provider' `
    --key-name ('azihsm-ca-' + [Guid]::NewGuid().ToString('N'))

.\crates\target\x86_64-pc-windows-msvc\release\azihsm-ca.exe serve `
    --state-dir C:\azihsm-demo\ca-state `
    --allow-dns server.demo.internal
```

In a second PowerShell terminal:

```powershell
.\crates\target\x86_64-pc-windows-msvc\release\azihsm-ca-demo.exe create `
    --output-dir C:\azihsm-demo\tls-server `
    --subject-cn server.demo.internal `
    --dns server.demo.internal `
    --ca-url http://127.0.0.1:8080 `
    --acknowledge-plain-http
```

The TLS private key remains non-exportable in AziHSM; the demo prints its
public wire transcript.

## Learning Resources

* **Certificate Authorities** (**CA**)
    * [What is a certificate authority?](https://www.youtube.com/watch?v=8ItJ-VqYo_s)
    * [Security-AzureConfidentialVM - `WincryptX509.cpp`](https://msazure.visualstudio.com/One/_git/Security-AzureConfidentialVM?path=%2Fsrc%2FSecretsProvisioningLibrary%2FWindows%2FWincryptX509.cpp) - Demonstration of using Windows APIs to construct, sign, load, and validate X509 certs.
    * [azure-cli-extensions - `create_certchain.sh`](https://github.com/Azure/azure-cli-extensions/blob/main/src/confcom/samples/certs/create_certchain.sh) - Shell script that uses OpenSSL on Linux to generate a certificate chain.
