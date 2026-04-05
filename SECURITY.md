# Security Model — Sibna Protocol v1.0.4

This document outlines the threat model, assumptions, and known limitations of the protocol.

## Project Status

Sibna implements modern cryptographic standards. **It has not undergone an independent external security audit.** It is intended for research and integration by advanced developers. Do not use in critical production environments without prior independent review.

## Threat Model

| Capability | Status |
|------------|--------|
| Passive Network Monitoring | Partially Addressed |
| Active MITM | Addressed (after Safety Number verification) |
| Local In-Memory Extraction | Addressed (`zeroize`) |
| Global Passive Adversary (GPA)| **Not fully addressed** |
| Local DB Extraction | Addressed (HMAC authentication) |

## Applied Protections

| Feature | Mechanism | Status |
|---------|-----------|--------|
| **Data Confidentiality** | ChaCha20-Poly1305 (256-bit) AEAD | ✅ Supported |
| **Post-Quantum Resistance**| Hybrid ML-KEM-768 + X25519 | ✅ Default |
| **Constant-time Integrity**| `subtle` crate comparisons | ✅ Supported |
| **Replay Protection** | Atomic message counters + timestamps | ✅ Supported |
| **Cover Traffic** | Poisson process distribution (avg 5s) | ✅ Supported |
| **Sealed Sender** | Server does not know sender identity | ✅ Supported |
| **Envelope Integrity** | Ed25519 + SHA-512 over all fields | ✅ Supported |

## Known Limitations

### 1. Global Passive Adversary (GPA)
Sibna provides padding and cover traffic but cannot completely protect against an adversary who can monitor the entire internet and perform traffic correlation. Users must manually configure Tor (`P2pConfig { proxy: Some("socks5://127.0.0.1:9050") }`) to achieve strong anonymity.

### 2. TOFU (Trust On First Use)
The initial key exchange is vulnerable to a Man-in-the-Middle (MITM) attack. The library pins identity keys to prevent subsequent tampering, but developers must implement out-of-band "Safety Number" verification to secure the first exchange.

### 3. Anonymity
Anonymity is not built-in by default. User IPs are visible to the server unless routing through SOCKS5 or Tor explicitly.

### 4. Side Channels
While `subtle` is used to prevent software timing attacks, there is no guarantee against hardware architectural side channels (e.g., Spectre, Meltdown).

## Vulnerability Disclosure

**Do not open public issues for security vulnerabilities.**

Email: `security@sibna.dev`
