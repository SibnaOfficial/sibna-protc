# Sibna Protocol v2.0.0 "Fortress"

Sibna is a high-assurance Rust implementation of the Signal Protocol (X3DH and Double Ratchet), engineered for robust end-to-end encryption (E2EE) in decentralized and peer-to-peer environments. It provides a standardized framework for secure, asynchronous, and forward-secret communication.

## Architectural Overview

Sibna v2.0.0 introduces several "Beyond-Paranoid" security enhancements designed to mitigate advanced threat vectors:

- **Transcript Binding (v10)**: Handshake keys are cryptographically bound to the full public key transcript using BLAKE3, preventing key-substitution and unknown key-share (UKS) attacks.
- **Stealth Handshake**: Implements identity obfuscation during the initial exchange, preventing passive metadata collection of participant public keys.
- **Hybrid Post-Quantum Security**: Merges classical X25519 Diffie-Hellman with ML-KEM-768 (FIPS 203) for quantum-resistant key encapsulation.
- **Memory Hardness**: Utilizes **Argon2id** for master password derivation, ensuring high resistance against GPU/ASIC-based brute-force attacks.
- **Memory Hygiene**: Forces sensitive entropy pools and transient key buffers into non-swappable RAM via `VirtualLock`/`mlock` and ensures zeroization on drop.

## Project Status

> [!IMPORTANT]
> **No independent external security audit has been performed on this implementation.** While Sibna utilizes audited cryptographic primitives from the RustCrypto ecosystem, the protocol orchestration itself should be treated as experimental for production-critical systems until a formal audit is completed.

## Core Components

- **`sibna-core`**: The primary cryptographic library containing ratchet logic, KDFs, and P2P handshake implementations.
- **`sibna-server`**: A lightweight, multi-transport relay (REST + WebSocket) for identity management and sealed envelope routing.
- **`sdks/`**: Native bindings for C++, Python, JavaScript (WASM), Flutter, Dart, and Go.

## Quick Start (Rust)

Add `sibna-core` to your `Cargo.toml`:

```toml
[dependencies]
sibna-core = { version = "2.0.0", features = ["pqc", "p2p", "relay"] }
```

### Basic Session Initiation

```rust
use sibna_core::{SecureContext, Config};
use sibna_core::handshake::x3dh;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize secure context with Argon2id protection
    let ctx = SecureContext::new(Config::default(), Some(b"MasterPassword"))?;

    // 2. Perform Stealth Handshake (Identity Hiding)
    let (session, handshake_output) = x3dh::initiator_v10(&ctx, &peer_prekey_bundle).await?;

    // 3. Encrypt with Double Ratchet (Perfect Forward Secrecy)
    let ciphertext = session.encrypt(b"Confidential payload")?;
    
    Ok(())
}
```

## Documentation

Comprehensive technical details are available in the following documents:

- **[Security Model](SECURITY.md)**: Threat model, limitations, and cryptographic invariants.
- **[Protocol Specification](PROTOCOL_SPECIFICATION.md)**: Bit-level description of handshakes and ratcheting.
- **[Changelog](CHANGELOG.md)**: Version history and security audit trail.

## License

This project is dual-licensed under the **Apache License 2.0** and the **MIT License**.
