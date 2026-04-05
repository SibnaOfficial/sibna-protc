# Changelog

All notable changes to the Sibna Protocol are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.4] - 2026-04-05

### Security - Critical Fixes
- **V1** `encryptor.rs`: Fixed Replay-Window gap. Ensure messages with higher sequence numbers don't bypass replay checks.
- **V2** `ratchet/session.rs`: Fixed unbounded deserialization. Bounded the deserialization of skipped message keys to prevent DoS/OOM.

### Security - High Severity Fixes
- **V3** `ratchet/state.rs`: Fixed private key bytes leakage and restoration confusion. Added `dh_local_public_bytes`.
- **V4** `crypto/kdf.rs`: Replaced simple hash implementation with proper HKDF-SHA256 for key derivation to prevent length-extension attacks.
- **V5** `server/main.rs`: Required JWT authentication for `delete_prekey_handler` to prevent unauthorized bundle deletion.

### Security - Medium & Low Fixes
- **V6** `server/auth.rs`: Enabled constant-time HMAC comparison via `subtle::ConstantTimeEq` to prevent timing oracles.
- **V7** `server/ws.rs`: Placed a strict hexadecimal payload length limit (20MB) to prevent WebSocket DoS bypassing HTTP limits.
- **V8** `server/main.rs`: Removed `DefaultHasher` usage for rate limiting in favor of string concatenation to prevent bucket collisions.
- **V10** `core/src/crypto/random.rs`: Removed OS RNG panics.
- **V11** `server/auth.rs`: Ensured strict parse failure rejections instead of defaulting timestamp to 0.
- **V12** `core/src/validation.rs`: Separated binary validation from string sanitization.

### Tooling & Documentation
- **Clippy**: Achieved zero-warning status by applying strict lint resolutions globally.
- **Documentation**: Translated all documentation to factual English and unified version references to 1.0.4.

---

## [0.9.0] - 2026-03-20

- Stabilized P2P discovery
- Introduced Post-Quantum mechanism

## [0.8.0] - 2024-XX-XX

- Initial robust E2EE implementation
