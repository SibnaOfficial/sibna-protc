# Changelog - Sibna Protocol

All notable changes to the Sibna Protocol are documented here. This project adheres to **Semantic Versioning (v2.0.0)**.

---

## [2.0.0] - 2026-04-05 - "Fortress" Release

The **Fortress Release** is a major architectural milestone focused on "Beyond-Paranoid" security hardening, metadata obfuscation, and state verification.

### Architectural Enhancements (Beyond-Paranoid)
- **Transcript Binding (v10)**: Integrated BLAKE3-based transcript hashing into the X3DH KDF to prevent key-substitution and unknown key-share (UKS) attacks.
- **Stealth Handshake**: Implemented encrypted identity bundles during the initial P2P exchange to prevent passive metadata leakage of participant public keys.
- **Argon2id Master KDF**: Replaced iterative HKDF with memory-hard **Argon2id** for master password-based key derivation (m=64MB, t=3, p=4).
- **Memory Pinning (VirtualLock)**: Enabled RAM-pinning for entropy pools and transient key buffers using `VirtualLock` (Windows) and `mlock` (Unix) to prevent disk-leakage via swap.
- **Multi-Device State Binding**: Incorporated a 128-bit `device_id` into the session KDF to ensure distinct ratchet chains and prevents nonce collisions across multi-device installs.

### Technical & Security Fixes
- **V1 (Replay Protection)**: Patched a sequence gap in `encryptor.rs` that allowed out-of-order message bypasses.
- **V2 (DoS mitigation)**: Bounded the deserialization of skipped message keys to prevent uncontrolled memory allocation.
- **V3 (Key Leakage)**: Resolved a memory exposure bug in `DoubleRatchetState` where private key buffers were not consistently zeroized after restoration.
- **V5 (Auth Binding)**: Enforced strict JWT authentication for all prekey management operations at the server level.
- **V8 (Rate Limiting)**: Refactored rate-balancer buckets to use collision-resistant identifiers (IP-Identity concatenation).

### Maintenance & Quality
- **Unified Versioning**: Synchronized version 2.0.0 across all core modules, relay server components, and multi-language SDKs (Python, JS, Go, C++, Dart, Flutter).
- **Professional Documentation**: Overhauled the technical documentation suite (README, SECURITY, PROTOCOL_SPECIFICATION) for accuracy, technical precision, and honest disclosure of project status.
- **Zero-Warning Status**: Completed a global lint sweep, resolving all high and medium-severity Clippy warnings.

---

## [0.9.0] - 2026-03-20
- Initial Post-Quantum mechanism integration (ML-KEM-768).
- Stabilized P2P discovery routing.

## [0.8.0] - 2024-XX-XX
- Core Double Ratchet implementation.
- X3DH classical handshake.
