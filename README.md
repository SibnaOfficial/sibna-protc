# Sibna Protocol

A Rust implementation of X3DH and the Double Ratchet algorithm for commercially-compatible E2EE.

---

**Notice**: This is an independent project. It is not affiliated with, endorsed by, or a fork of the Signal Technology Foundation or Signal Messenger.

---

## Overview

Sibna is a cryptographic library providing an independent implementation of Signal-style end-to-end encryption (E2EE). It is designed to be integrated into proprietary or open-source applications where Signal's official app-specific infrastructure or GPLv3 licensing is not a fit.

- **Asynchronous Handshake**: Extended Triple Diffie-Hellman (X3DH).
- **Continuous Re-keying**: Double Ratchet algorithm for forward secrecy and post-compromise security.
- **Quantum Resistance (Default ON)**: Hybrid X25519 + ML-KEM-768 (FIPS 203) handshake. The session key is secure as long as *either* primitive is unbroken.
- **Group Messaging**: Sender Key pattern.
- **Licensing**: Apache 2.0 / MIT (Permissive).

## Quick Start (Rust)

```rust
use sibna_core::{SecureContext, Config};
use sibna_core::crypto::{CryptoHandler, KeyGenerator};

// 1. Initialize context
let config = Config::default();
let ctx = SecureContext::new(config, Some(b"SecurePass123!"))?;

// 2. Identity generation
let identity = ctx.generate_identity()?;

// 3. Encrypt payload
let key     = KeyGenerator::generate_key()?;
let handler = CryptoHandler::new(key.as_ref())?;

let ciphertext = handler.encrypt(b"Hello world", b"aad")?;
let plaintext  = handler.decrypt(&ciphertext, b"aad")?;
```

## Security & Architecture

Sibna focuses on technical transparency. The table below states exactly what this library does and does not provide.

### What This Library Provides

| Property | Status | Notes |
|---|---|---|
| Message Confidentiality | ✅ | ChaCha20-Poly1305 AEAD |
| Forward Secrecy | ✅ | Symmetric ratchet re-keys every message |
| Post-Compromise Security | ✅ | DH ratchet re-keys after round-trips |
| **Quantum Resistance** | ✅ **Default ON** | Hybrid X25519 + ML-KEM-768 (FIPS 203) |
| Memory Key Zeroization | ✅ | via `zeroize` |

### What This Library Does NOT Provide

> [!CAUTION]
> These are architectural constraints, not bugs. Integrators must handle them explicitly.

| Limitation | Description |
|---|---|
| **Partial Metadata Exposure** | Traffic sizes are mitigated by our **built-in PaddingMode** (defaults to 1KB blocks), but timing and who-talks-to-whom logic remain visible unless network-anonymity is leveraged. |
| **Anonymity requires Tor** | Anonymity is **only** achieved if you configure the library's `P2pConfig::proxy` field with a SOCKS5 proxy (e.g. `127.0.0.1:9050` for Tor). Without it, local IP and addresses are exposed. |
| **Trust-On-First-Use (TOFU) limits** | The library securely pins Peer Identity Keys, automatically breaking connections if a MITM swapped the key later. However, **Safety Numbers must still be verified out-of-band** to prove the very first initially-pinned key. |

### Quantum Resistance Details

- **Default**: Both X25519 and ML-KEM-768 contribute to the session key. A quantum computer must break *both* to compromise a session.
- **Without `pqc` feature**: X25519 only — vulnerable to a sufficiently capable quantum computer.
- To disable: `sibna-core = { default-features = false, features = ["std"] }`

## Production Status

**Critical**: This library is NOT production-ready for high-risk environments.

- **No External Audit**: NO independent external security audit has been performed yet.
- **Internal Hardening**: v1.0.0 includes fixes for logic errors identified in internal review.
- **Roadmap**: Targeting external cryptography audit for Q3 2026.

See [SECURITY.md](SECURITY.md) and [PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md) for full threat model details.

## License

Dual-licensed under Apache License 2.0 and MIT.
