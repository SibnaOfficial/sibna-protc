# Sibna Protocol

Sibna Protocol is a Rust implementation of the X3DH and Double Ratchet cryptographic protocols designed for robust end-to-end encryption (E2EE). It is dual-licensed under Apache 2.0 and MIT.

## Overview

Sibna is a cryptographic library providing a standalone protocol for end-to-end encryption. It is designed to be integrated into applications that require secure communication channels without relying on external infrastructure.

### Core Features

- Perfect Forward Secrecy & Post-Compromise Security
- Hybrid cryptography integrating classical X25519 and ML-KEM-768 (FIPS 203)
- Fixed-block message padding to prevent length analysis
- Sealed Sender envelopes for metadata protection
- Direct P2P and relayed transport routing

## Quick Start (Rust)

Add `sibna_core` to your `Cargo.toml`:

```toml
[dependencies]
sibna_core = { path = "core", version = "1.0.4", features = ["pqc", "relay"] }
```

Example usage:

```rust
use sibna_core::{SecureContext, Config};
use sibna_core::crypto::{CryptoHandler, KeyGenerator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let ctx = SecureContext::new(config, Some(b"SecurePass123!"))?;

    let session_key = KeyGenerator::generate_key()?;
    let handler = CryptoHandler::new(session_key.as_ref())?;

    let aad = b"header_data";
    let ciphertext = handler.encrypt(b"System payload", aad)?;
    let plaintext = handler.decrypt(&ciphertext, aad)?;

    assert_eq!(plaintext, b"System payload");
    Ok(())
}
```

## Documentation

- [Protocol Specification](PROTOCOL_SPECIFICATION.md)
- [Security Model](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

This project is dual-licensed under the Apache License 2.0 and the MIT License. See the LICENSE file for details.
