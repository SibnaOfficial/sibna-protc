# Security Model & Threat Assessment

This document provides a technical appraisal of the Sibna Protocol's security posture, emphasizing architectural invariants, the assumed threat model, and critical limitations.

## Project Maturity & Assurance

> [!WARNING]
> **Sibna Protocol v2.0.0 is an independent cryptographic implementation.** While it leverages high-assurance primitives from the `RustCrypto` ecosystem, the protocol orchestration has **not** been subjected to an external security audit. Implementers are advised to conduct their own peer review before integrating Sibna into high-stakes environments.

## Threat Model (Sibna v2.0.0 "Fortress")

Sibna is designed to protect communication against a pervasive network adversary with the capability to intercept, modify, and drop packets.

### 1. Covered Attack Vectors
- **Key Substitution & UKS**: Mitigated via BLAKE3 Transcript Binding (v10 KDF).
- **Identity Leakage**: Mitigated via the Stealth P2P Handshake (Identity Obfuscation).
- **Post-Compromise Recovery**: Guaranteed via the asynchronous Double Ratchet Diffie-Hellman update.
- **Forward Secrecy**: Guaranteed via the HMAC-SHA256 based Chain Key derivation.
- **Master Password Cracking**: Hardened via **Argon2id** (m=64MB, t=3, p=4) memory-hard KDF.
- **Memory Leakage**: Mitigated via `VirtualLock`/`mlock` RAM pinning and `Zeroize` on drop.
- **Storage Rollback**: Mitigated via serialized `StorageManifest` state-sequence verification.

### 2. Network-Level Threats (GPA)
Sibna does **not** provide inherent protection against a Global Passive Adversary (GPA) capable of monitoring large portions of the internet.
- **Traffic Correlation**: While Sibna uses fixed-block padding, timing and volume analysis remains an open vector for powerful adversaries.
- **Anonymity**: Sibna is a cryptographic protocol, not an anonymity network. IP addresses are visible to the relay or P2P peer unless routed via Tor/SOCKS5.

### 3. Trust Invariants (TOFU)
The protocol operates on a **Trust On First Use (TOFU)** basis for the initial X3DH handshake. 
- **Authenticity**: Users **must** perform out-of-band verification (e.g., comparing Safety Numbers via QR codes or voice) to guarantee the identity of the remote peer. Failing this step allows for an active Man-In-The-Middle (MITM) attack during the initial key exchange.

### 4. Side Channels
- **Cryptographic**: All core operations use standard constant-time implementations (via `subtle`).
- **Architectural**: No protection is provided against low-level hardware side channels (e.g., Spectre, Meltdown).

## Cryptographic Specification (Invariants)

| Primitive | Algorithm | Security Level |
| :--- | :--- | :--- |
| **KEM (Quantum)** | ML-KEM-768 | NIST Category 3 |
| **DH (Classical)** | X25519 | ~128-bit |
| **AEAD** | ChaCha20-Poly1305 | 256-bit |
| **KDF** | HKDF-SHA256 | - |
| **Hashing** | BLAKE3 (Transcript) / SHA-512 | - |
| **Signatures** | Ed25519 | - |
| **Password KDF** | Argon2id | - |

## Vulnerability Disclosure

If you identify a cryptographic defect or architectural vulnerability, please report it to `security@sibna.dev`.
