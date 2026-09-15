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
| Implement Mock CLA | TODO | |
| Implement TLS Server | TODO | |
| Test TLS-Server-to-Mock-CLA certificate issuing | TODO |
| Implement TLS Client | TODO | |
| Test TLS-Client-to-TLS-Server communication | TODO | |
| Test full workflow | TODO | |
| Record demonstration of full workflow | TODO | |

## Learning Resources

* **Certificate Authorities** (**CA**)
    * [What is a certificate authority?](https://www.youtube.com/watch?v=8ItJ-VqYo_s)
    * [Security-AzureConfidentialVM - `WincryptX509.cpp`](https://msazure.visualstudio.com/One/_git/Security-AzureConfidentialVM?path=%2Fsrc%2FSecretsProvisioningLibrary%2FWindows%2FWincryptX509.cpp) - Demonstration of using Windows APIs to construct, sign, load, and validate X509 certs.
    * [azure-cli-extensions - `create_certchain.sh`](https://github.com/Azure/azure-cli-extensions/blob/main/src/confcom/samples/certs/create_certchain.sh) - Shell script that uses OpenSSL on Linux to generate a certificate chain.

