# Sibna Protocol v3.0.1 

A high-security Rust implementation of the X3DH and Double Ratchet protocol — E2EE dual-licensed under Apache 2.0 / MIT.

> [!CAUTION]
> **Security Disclaimer**: This protocol is currently an experimental research prototype and has not yet undergone formal third-party cryptographic review or independent security audit. It should be used for research and evaluation purposes only.

---

> [!IMPORTANT]
> **Status: Security-Hardened Research Prototype (Pre-Audit)**.
> Sibna v3.0.1 is an architectural implementation designed for high-assurance metadata resistance. It has been evaluated against timing side-channels via internal statistical benchmarking. A formal 3rd-party independent audit is targeted for Q3 2026.

---

## Core Features

### Core Cryptography
- **X3DH v3 + Transcript Binding**: BLAKE3-based binding to prevent UKS attacks.
- **Double Ratchet**: Forward Secrecy and Post-Compromise Security.
- **Hybrid PQC (Post-Quantum)**: Standard X25519 combined with ML-KEM-768 (FIPS 203).
- **Memory Security**: `Zeroize` on drop and memory pinning (`mlock`) for sensitive keys.

### Transport & Networking
- **mDNS / Stealth Handshake**: Identity-hiding discovery in P2P environments.
- **Relay Support**: Native SOCKS5 and Tor transport integration.
- **WebRTC Signaling**: Routing support for high-bandwidth media sessions.
- **Delivery ACKs**: Reliable delivery with zero message loss.

### Privacy & Metadata Resistance
- **Sealed Sender (Blinded Relay)**: Infrastructure designed to minimize sender metadata at the relay layer.
- **Metadata Obfuscation**: Hardened padding (1KB default, up to 64KB) with random noise prefixes.
- **Cover Traffic**: Exponentially distributed dummy packets to mitigate traffic analysis.

---

## Quick Start

```toml
[dependencies]
sibna-core = { version = "3.0.1", features = ["pqc", "p2p"] }
```

```rust
use sibna_core::{SecureContext, Config};

// Initialize context (Argon2id protects storage if enabled)
let ctx = SecureContext::new(Config::default(), Some(b"MasterPassword"))?;
let identity = ctx.generate_identity()?;

// Send a message (automatically routes via P2P or Relay)
let mut router = HybridRouter::new(ctx);
router.send_message(&recipient_id, b"Hello").await?;
```

---

| Property | Safeguard | Implementation Status |
|----------|-----------|--------|
| **Identity (MITM)** | `Config::fortress_mode()` enforces Safety Number verification. | Policy Enforced |
| **Traffic Analysis** | **Fixed-size padding** (up to 64KB) + Poisson Cover Traffic. | Logic Implemented |
| **Anonymity** | Native SOCKS5/Tor transport support integrated. | Logic Integrated |
| **Side Channels** | No statistically significant timing difference under bench tests. | Under Evaluation |
| **Rate Limiting** | Constant-time authentication path implementation. | Logic Implemented |

## Documentation

- [SECURITY.md](SECURITY.md) — Threat model and formal limitations
- [PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md) — Technical Specification
- [CHANGELOG.md](CHANGELOG.md) — Release History

## License

Apache License 2.0 / MIT (Dual)
