# Security & Assessment

This document outlines the security model and implementation status of the Sibna Protocol.

## 1. Audit Status

**NOT production-ready for high-risk environments without external audit.**

Version 1.0.0 represents a state of "internal hardening." While previous internal logic errors have been addressed, the implementation has not been reviewed by an independent security firm.

**Roadmap**:
- Targeting independent external audit: Q3 2026.

## 2. Vulnerability Reporting

Send reports to [security@sibna.dev](mailto:security@sibna.dev). Please do not open public GitHub issues for security vulnerabilities.

- Acknowledgment: 48 hours.
- Assessment: 7 days.

## 3. Threat Model

Assurances are based on specific implementation and environment assumptions.

### 3.1 Provided Protections
- **Confidentiality**: AEAD via ChaCha20-Poly1305.
- **Forward Secrecy**: Symmetrical ratchet re-keying on every message.
- **Post-Compromise Security**: DH ratchet re-keying after round-trip exchanges.
- **Memory Security**: Automatic zeroization of sensitive buffers on drop.

### 3.2 Constraints & Assumptions
- **MITM Protection**: Requires manual, out-of-band Safety Number verification.
- **Endpoint Security**: Assumes the host OS/hardware is not compromised.
- **Randomness**: Relies on the host OS CSPRNG.

### 3.3 Out of Scope
- **Metadata**: No protection against traffic analysis or participant profiling.
- **Quantum Resistance**: Current asymmetric primitives (Curve25519) are not PQ-secure.

## 4. Hardening (v1.0.0)

Key fixes applied during internal review:
- **HKDF Domain Separation**: Enforced unique constants to prevent key reuse across session versions.
- **Panic Removal**: Replaced all production `.unwrap()`/`.expect()` with proper error propagation.
- **Rate Limiting**: Enforced bounds (e.g., 500 skipped messages) to prevent memory exhaustion DoS.

## 5. Integration Checklist

1. **Key Storage**: Secure private keys (e.g., Secure Enclave / encrypted storage).
2. **Verification**: Implement UI for manual Safety Number comparison.
3. **Persistence**: Ensure session state is saved/loaded securely.

Last Updated: March 2026
