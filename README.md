# AziHSM TLS Proof-of-Concept

[**Azure Integrated HSM**](https://github.com/microsoft/AziHSM-Guest) (**AziHSM**) is a **Hardware Security Module** (**HSM**) that enables the creation, caching, and usage of cryptographic keys within an isolated hardware environment.
Latest Azure VM generations have the option to attach to a local AziHSM device, which can be used to store keys locally and use the AziHSM device's crypto engines to perform crypto operations.

AziHSM supports a variety of customer scenarios.
However, throughout our testing and development, one scenario we haven't visited is using AziHSM to manage keys for a [**Transport Layer Security**](https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/) (**TLS**) server.
This project aims to explore that scenario; this repository contains the files and code from our 2026 hackathon project.

## Project Agenda

| **Task** | **Status** | **Description** |
|----------|------------|-----------------|
| Research TLS | 🔳 Todo | Gain a basic understanding of TLS; how it works, what keys and certificates are used. Start to form an idea of what a AziHSM-enabled TLS server would look like. |
| Research Windows API | 🔳 Todo | Study the Windows cryptographic API; understand what API calls our PoC TLS server would need to make to perform TLS operations, and to communicate with AziHSM. |
| Develop PoC TLS Server+Client | 🔳 Todo | Create a basic command-line TLS server and client (preferably in Rust) that we can use to have two AziHSM-enabled Azure VMs talk to each other. |
| Test cross-VM communication with TLS server+client | 🔳 Todo | |
| Record demonstration of cross-VM TLS communication | 🔳 Todo | |

