# Sibna Protocol

A Rust re-implementation of X3DH and the Double Ratchet algorithm for commercially-compatible E2EE.

---

**Notice**: This is an independent project. It is not affiliated with, endorsed by, or a fork of the Signal Technology Foundation or Signal Messenger.

---

## Overview

Sibna is a cryptographic library providing an independent implementation of Signal-style end-to-end encryption (E2EE). It is designed to be integrated into proprietary or open-source applications where Signal's official app-specific infrastructure or GPLv3 licensing is not a fit.

- **Asynchronous Handshake**: Uses the Extended Triple Diffie-Hellman (X3DH) design.
- **Continuous Re-keying**: Uses the Double Ratchet algorithm for forward secrecy and post-compromise security.
- **Group Messaging**: Uses the Sender Key pattern (Reference: Signal "Sender Keys" design).
- **Licensing**: Apache 2.0 / MIT (Permissive).

## Quick Start (Rust)

Initialize a context and encrypt a message:

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

Sibna focus is on technical transparency. It makes no claims of anonymity or metadata protection.

### Core Guarantees
- Forward Secrecy & Post-Compromise Security.
- AEAD Integrity (ChaCha20-Poly1305).
- Automated memory zeroization (via `zeroize`).

### Non-Goals / Out of Scope
- **Metadata Protection**: No shielding of traffic timing, packet sizes, or identities.
- **Post-Quantum Security**: Primary X25519 primitives are not quantum-resistant.
- **Anonymity**: No native onion-routing or traffic obfuscation.

### Implementation Checklist
- **Serialization**: Binary format safety (bincode with limits).
- **State Transitions**: Validated session-state logic.
- **Key Reuse**: Enforced unique nonces and KDF paths.

## Production Status

**Critical**: This library is NOT production-ready for high-risk environments.

- **Hardening**: v1.0.0 includes internal fixes for identified logic errors.
- **Audit**: NO independent external security audit has been performed yet.
- **Roadmap**: Targeting external cryptography audit for Q3 2026.

See [SECURITY.md](SECURITY.md) and [PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md) for details.

## License

Dual-licensed under Apache License 2.0 and MIT.
