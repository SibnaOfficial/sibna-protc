# Sibna Protocol Security Model

This document outlines the security model, trust assumptions, and known limitations of the Sibna Protocol (v1.0.3).

## Project Status

Sibna is an experimental protocol implementation. While it incorporates modern cryptographic standards (hybrid X25519 + ML-KEM-768), it has **not** undergone a formal external security audit. It is designed for researchers and advanced users, not for mission-critical production use without prior independent verification.

## Threat Model

### Adversary Capabilities
We consider an adversary who can:
- **Passively observe**: Monitor network traffic between peers or between a peer and the relay.
- **Actively intercept**: MITM connections, drop, or inject packets.
- **Compromise temporary state**: Access ephemeral secrets in memory (mitigated by `Zeroize`).
- **Global Passive Adversary (GPA)**: An opponent that can monitor large portions of the global internet backbone.

### Protections Provided
| Feature | Mitigation | Status |
|---|---|---|
| **Data Confidentiality** | ChaCha20-Poly1305 (256-bit) AEAD | Supported |
| **Quantum Resistance** | Hybrid ML-KEM-768 + X25519 Handshake | Supported |
| **Integrity Checks** | Constant-Time comparisons | Supported |
| **Replay Protection** | Atomic Message Counters + Timestamping | Supported |
| **Traffic Masking** | Jittered Cover Traffic | Supported |
| **Metadata Protection** | Constant-size (1KB) blocks + Padding | Supported |

### Critical Limitations

#### 1. Global Passive Adversaries (GPA)
While Sibna provides padding and optional cover traffic, it **cannot** fully protect against an adversary who sees the entire global network graph. Such an opponent can perform sophisticated **traffic correlation** and **statistical analysis** to link sender/receiver pairs.

#### 2. Anonymity vs Transport Proxy
The built-in SOCKS5/Tor support is a **transport option**, not a built-in anonymity guarantee. Routing traffic through Tor hides your IP from the recipient, but does not prevent the provider from seeing that you are using the Sibna protocol unless additional obfuscation (Bridges/Pluggable Transports) is used.

#### 3. Trust-On-First-Use (TOFU)
The initial exchange remains vulnerable to a MITM attack. Users **must** verify "Safety Numbers" (fingerprints) out-of-band for absolute assurance of identity.

#### 4. Side-Channel Resistance
We use the `subtle` crate to prevent timing attacks in code, but we cannot guarantee resistance against lower-level micro-architectural side channels (e.g., Spectre, Meltdown) or hardware-level probes.

## Security Reporting
Please report vulnerabilities privately via [security@sibna.dev].
