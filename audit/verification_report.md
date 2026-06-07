# Sibna Protocol v3.0.1 Verification Report

## 1. Executive Summary
The Sibna Protocol v3.0.1 has undergone a comprehensive stabilization and security hardening process. All critical build errors were resolved, a deadlock in the Header Encryption (v3.1) was fixed, and SDK test coverage was significantly expanded across multiple platforms.

## 2. Critical Fixes
### 2.1 Core Build Stability
- Resolved multiple type inference errors (`E0282`) in `core/src/manager.rs`.
- Fixed brace mismatches and syntax errors in the key rotation loop.
- Gated P2P-specific methods behind the `p2p` feature flag to prevent compilation failures in non-P2P builds.
- Fixed `get_signed_prekey` and `to_bytes` errors in the Handshake Builder.

### 2.2 Header Encryption Deadlock (v3.1)
- **Issue**: Encrypted headers prevented the receiver from seeing the `dh_public` key necessary to perform a DH ratchet, creating a "chicken-and-egg" deadlock.
- **Solution**: Modified the encryption path to send headers in **plaintext** specifically when a DH rotation has occurred. Subsequent messages in the same chain use encrypted headers.
- **Verification**: Verified via `test_serialize_deserialize_roundtrip_can_send` in Rust core.

## 3. SDK Test Expansion
To ensure cross-platform consistency, tests were ported from the Rust core and C++ SDK to other platforms.

### 3.1 Java SDK
- Added `serialize()`, `deserialize()`, and `getStats()` to `DoubleRatchet.java`.
- Implemented empty plaintext validation.
- Expanded `SessionTest.java` to include:
    - Full Encrypt/Decrypt roundtrip.
    - Replay attack protection.
    - State serialization/restoration.
    - Session statistics verification.

### 3.2 Dart & Flutter SDKs
- Added `fromSharedSecret` factory to `SibnaSession` to enable isolated ratchet testing.
- Expanded `session_test.dart` (Dart) and `session_test.dart` (Flutter) to cover:
    - Plaintext and ciphertext validation (empty inputs).
    - Session stats verification.
    - Native handle flow verification.

## 4. Formal Verification
A formal cryptographic model was created using the **ProVerif** language (`audit/formal_verification/sibna_v3.pv`).
- **Properties Modeled**: Session secrecy, Forward Secrecy, and authenticity of the Double Ratchet.
- **Model Scope**: Includes the v3.1 Header Encryption logic and AEAD-based message protection.

## 5. Final Status
| Component | Status | Note |
| :--- | :--- | :--- |
| Core Build | ✅ Stable | All targets compile successfully. |
| v3.1 Logic | ✅ Fixed | Deadlock resolved and verified. |
| Java SDK | ✅ Verified | Comprehensive tests implemented. |
| Dart SDK | ✅ Verified | Comprehensive tests implemented. |
| Flutter SDK | ✅ Verified | Comprehensive tests implemented. |
| Formal Model | ✅ Created | Ready for automated verification. |

**Status: v3.0.1 is "hardened and pre-audit ready" — NOT certified production-ready.**

This report documents the v3.0.1 stabilisation pass. It is **not** a
production-readiness certification. The audit verdict in
[`audit/EXECUTIVE_BRIEF.md`](EXECUTIVE_BRIEF.md) is the authoritative
assessment and identifies residual risk dimensions that this report
does not address:

- **At-rest storage** — `manifest` deletion defeats rollback protection;
  `device_id` is wiped on `load_from_disk`; lock file leaks on panic
  (see `AUDIT_REPORT.md` § At-rest storage table).
- **Network metadata** — mDNS broadcasts random session tokens in
  cleartext on LAN (P2P path only); only outgoing connections can be
  SOCKS5-routed.
- **Build hygiene** — `fips203 0.4.3` final-FIPS-203 alignment is
  unverified.
- **External review** — No independent third-party cryptographic audit
  has been performed. The EXECUTIVE_BRIEF targets Q3–Q4 2026 contingent
  on integration tests passing in CI.

See `EXECUTIVE_BRIEF.md` § "Final word" for the full recommendation
(verbatim: "Block production deployment").
