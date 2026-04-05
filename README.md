# Sibna Protocol

A Rust implementation of the X3DH and Double Ratchet cryptographic protocols designed for end-to-end encryption (E2EE). Dual-licensed under Apache 2.0 / MIT.

## Overview

Sibna is a cryptographic library providing a standalone protocol for end-to-end encryption. It is designed to be integrated into commercial or open-source applications needing secure communication channels.

| Feature | Status | Details |
|---------|--------|---------|
| **Message Confidentiality** | ✅ Supported | ChaCha20-Poly1305 AEAD |
| **Forward Secrecy** | ✅ Supported | Symmetric ratchet updates key with every message |
| **Post-Compromise Security**| ✅ Supported | DH ratchet reinitializes after every round trip |
| **Post-Quantum Crypto** | ✅ Default | Hybrid X25519 + ML-KEM-768 (FIPS 203) |
| **Message Padding** | ✅ Supported | Fixed-block padding (256 B → 16 KB) |
| **Cover Traffic** | ✅ Supported | Poisson exponential distribution |
| **P2P Authentication** | ✅ Supported | Direct X3DH over TCP |
| **Encrypted Relay** | ✅ Supported | WebSocket + Sealed Sender |
| **SOCKS5 / Tor** | ✅ Supported | `P2pConfig::proxy` or `RelayClient::new` |
| **Group Messaging** | ✅ Supported | Sender Key pattern |
| **FFI Bindings** | ✅ Supported | C/Flutter/Python supported |

## Quick Start (Rust)

```rust
use sibna_core::{SecureContext, Config};
use sibna_core::crypto::{CryptoHandler, KeyGenerator};

// 1. Initialize context
let config = Config::default();
let ctx = SecureContext::new(config, Some(b"SecurePass123!"))?;

// 2. Generate identity
let identity = ctx.generate_identity()?;

// 3. Encrypt and decrypt
let key     = KeyGenerator::generate_key()?;
let handler = CryptoHandler::new(key.as_ref())?;

let ciphertext = handler.encrypt(b"Hello world", b"aad")?;
let plaintext  = handler.decrypt(&ciphertext, b"aad")?;
```

## Hybrid Routing (P2P + Relay)

`HybridRouter` implements a peer-to-peer first policy:

- Attempts direct P2P connection if an active session is available
- Falls back to server relay if P2P fails
- Supports local device discovery via mDNS

## Status: v1.0.4

- Automated verification includes 12 protocol attack vectors.
- See `SECURITY.md` for the threat model and limitations.
- See `PROTOCOL_SPECIFICATION.md` for technical implementation details.

## License

Apache License 2.0 / MIT
