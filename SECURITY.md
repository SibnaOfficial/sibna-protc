# Security & Assessment

This document outlines the security model and implementation status of the Sibna Protocol.

## 1. Audit Status

**NOT production-ready for high-risk environments without external audit.**

Version 1.0.0 represents a state of "internal hardening." While previous internal logic errors have been addressed, the implementation has **NOT** been reviewed by an independent security firm.

**Roadmap**:
- Targeting independent external audit: Q3 2026.

## 2. Vulnerability Reporting

Send reports to [security@sibna.dev](mailto:security@sibna.dev). Please do not open public GitHub issues for security vulnerabilities.

- Acknowledgment: 48 hours.
- Assessment: 7 days.

## 3. Threat Model

### 3.1 Provided Protections

| Property | Status | Mechanism |
|---|---|---|
| **Message Confidentiality** | ✅ Provided | ChaCha20-Poly1305 AEAD |
| **Forward Secrecy** | ✅ Provided | Symmetric ratchet re-keys every message |
| **Post-Compromise Security** | ✅ Provided | DH ratchet re-keys after round-trips |
| **Quantum Resistance** | ✅ Default ON | Hybrid X25519 + ML-KEM-768 (FIPS 203) |
| **Memory Safety** | ✅ Provided | Auto-zeroization of keys via `zeroize` |

#### Quantum Resistance — Hybrid Handshake (Default)

The `pqc` feature is **enabled by default**. Every X3DH handshake fuses two independent shared secrets:
- **Classical**: X25519 Diffie-Hellman
- **Post-Quantum**: ML-KEM-768 (FIPS 203, CRYSTALS-KYBER)

Both secrets are concatenated before HKDF, so the session key is secure as long as **either** primitive remains unbroken. This is the NIST-recommended hybrid approach.

> **To disable PQC** (e.g., for constrained environments):
> ```toml
> sibna-core = { default-features = false, features = ["std"] }
> ```
> **Warning**: Without the `pqc` feature, X25519 alone is vulnerable to a sufficiently capable quantum computer.

---

### 3.2 Known Limitations (Out of Scope)

These are **fundamental design constraints**, not bugs. Integrators must account for them.

#### ⚠️ Partial Metadata Protection

**What is mitigated:**
- **Packet sizes**: The library now utilizes `PaddingMode::Standard` (1KB blocks) by default. This makes size-based traffic analysis (guessing message contents by packet size) computationally unviable.

**What is exposed (Out of Scope):**
- Network identities and timing (when messages are sent and received).
- Who is communicating with whom (participant graph).

**Mitigation:** Route traffic through a VPN or mix network using the built-in SOCKS5 functionality if full metadata protection is required.

---

#### ⚠️ Anonymity via SOCKS5 Only

By default, IP addresses and network topologies are exposed. 
To achieve anonymity, **you must configure the built-in SOCKS5 integration**:
```rust
let mut config = P2pConfig::default();
config.proxy = Some("127.0.0.1:9050".parse().unwrap());
```
This forces the entire protocol layer, peer-discovery, and handshaking to wrap inside the Tor network natively. **Without this flag enabled, no anonymity is provided.**

---

#### ⚠️ TOFU MITM Protection & Pinning

This library features built-in Trust-On-First-Use (TOFU) peer pinning. 

1. On first contact, the **Peer Identity Key is cryptographically pinned** to local storage.
2. If a Man-In-The-Middle attempts to intercept a later connection by rotating the identity key, the Handshake will actively abort (`ProtocolError::KeyMismatch`).
3. **Manual Verification Requirement:** While the pin prevents active interception *after* first-contact, the very first key pinned could be a MITM. **Safety Numbers** (`SafetyNumber::calculate()`) must still be verified out-of-band to establish ultimate trust.

---

#### ⚠️ Endpoint Security Assumed

- The host OS and hardware are assumed to be uncompromised.
- The OS-provided CSPRNG (`getrandom`) is assumed to produce sufficient entropy.

---

### 3.3 Constraints Summary

| Limitation | Impact | Mitigation |
|---|---|---|
| TOFU Initial MITM vulnerability | Active MITM possible only during first contact before Safety Number check | Implement Safety Number UI in your app |
| Remaining Metadata | Communication graph is visible despite size-padding | Enable the internal `proxy` field for SOCKS5 |
| PQC disabled → X25519 only | Vulnerable to quantum adversary | Keep default `pqc` feature enabled |

## 4. Hardening (v1.0.0)

Key fixes applied during internal review:

- **HKDF Domain Separation**: Enforced unique constants to prevent key reuse across session versions.
- **Panic Removal**: Replaced all production `.unwrap()`/`.expect()` with proper error propagation.
- **Rate Limiting**: Enforced bounds (e.g., 500 skipped messages) to prevent memory exhaustion DoS.
- **QR MAC Key**: Removed secret MAC key from serialized QR payload (was a critical key-exposure bug).
- **Shared Secret Exposure**: `perform_handshake()` no longer returns raw shared secret to caller.

## 5. Integration Checklist

1. **Safety Number UI**: Implement a UI for manual Safety Number comparison after every new session.
2. **Key Storage**: Store private keys in Secure Enclave or encrypted storage.
3. **PQC Feature**: Ensure the `pqc` feature remains enabled (it is the default).
4. **Metadata**: If metadata privacy is required, integrate a transport-layer anonymity network.
5. **Persistence**: Ensure session state is saved/loaded securely.

Last Updated: April 2026
