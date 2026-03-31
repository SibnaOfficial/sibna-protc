# Changelog

## [1.0.0] - 2026-03-28
### Added
- **Full FFI Session Lifecycle**: Added `sibna_generate_identity`, `sibna_generate_prekey_bundle`, `sibna_perform_handshake`, `sibna_session_encrypt`, and `sibna_session_decrypt` allowing full X3DH and Double Ratchet usage from C/C++/Flutter/Python via FFI.
- **Persistent Keystore**: Added `save_to_disk` and `load_from_disk` to `KeyStore` allowing persistence of Identity and Prekeys to disk, encrypted with ChaCha20-Poly1305. Opt-in via `persistent` feature (using `sled`).
- **Ed25519 Challenge-Response**: Added `generate_challenge` and `verify_signed_challenge` for real cryptographic authentication.
- **WASM Bindings**: Added `wasm.rs` exposing all session/handshake functions to JavaScript/TypeScript via `wasm-bindgen`.
- **Prekey Server (`sibna-server`)**: Added a new workspace crate running an in-memory Axum HTTP server for PreKeyBundle upload and retrieval.

### Fixed
- Fixed compile error in `IdentityKeyPair::from_bytes` returning incorrect type and proper error propagation.
- Fixed `lib.rs` loading identity with wrong signature.



All notable changes to the Sibna Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-03-20

### Security — Critical fixes

* **HKDF session init**: Replaced dual `expand()` on same PRK with single 64-byte expand + split
* **QR code mac_key**: Removed secret MAC key from serialized QR payload (was leaking private key)
* **Shared secret exposure**: `perform_handshake()` no longer returns raw shared_secret to caller
* **chain.rs derive_key**: Fixed `?` operator used inside non-Result return type (compile/panic bug)
* **keystore::from_bytes**: Converted from panic-on-error to `ProtocolResult<Self>`

### Security — High severity fixes

* **Group DoS prevention**: Added `MAX_SKIP_GROUP=500` bound in `GroupSession::decrypt()`
* **Encryptor counter**: Fixed `initial_message_number=u64::MAX` → `0` (broke replay detection)
* **session.rs panics**: Replaced 4 `.unwrap()` calls in `skip_message_keys()` with `?`
* **add_group_member**: Propagated `ProtocolResult` from `add_member()` (was silently ignored)
* **builder.rs panic**: Replaced `SecureRandom::new().unwrap()` with proper error propagation
* **constant_time_cmp**: Documented as non-constant-time, hidden from public API

### Security — Medium severity fixes

* **MAX_AD_LEN alignment**: Unified validation limit (1024→256) with crypto layer limit
* **FFI last_error**: Implemented thread-local error storage (was always returning generic message)
* **burst_tokens init**: Fixed initialization to `0` from `100` (rate limiter was ineffective initially)
* **X3DH HKDF salt**: Replaced empty `&[]` salt with domain-separation constant
* **Debug log files**: Removed 30 `errors_v*.log` files from repository

### Changed

* Version bumped to 0.9.0
* `bincode` dependency: replaced RC version `2.0.0-rc.3` with stable `1.3.3`
* `aes-gcm` dependency: removed (unused, increases attack surface)
* Integration tests: completely rewritten with realistic scenarios

### Added

* `.github/workflows/ci.yml` — CI/CD with security audit, Miri, cross-platform tests
* `deny.toml` — cargo-deny dependency policy (license + advisory + ban rules)
* `clippy.toml` — strict clippy configuration
* `rustfmt.toml` — unified code formatting
* `.cargo/config.toml` — build configuration and shortcuts
* `CONTRIBUTING.md` — security-first contribution guidelines

## [0.8.0] - 2024-XX-XX

### Security

#### Critical Fixes
- **Memory Zeroization**: All sensitive data now properly zeroized on drop using `zeroize` crate
- **Secure Serialization**: Session state now serialized with encrypted binary format instead of JSON
- **Key Storage**: Skipped message keys now stored with automatic expiration and secure cleanup

#### High Severity Fixes
- **Input Validation**: Comprehensive validation added for all external-facing APIs
- **Rate Limiting**: DoS protection implemented for all cryptographic operations
- **Timing Attack Prevention**: Constant-time comparison operations throughout
- **Authentication**: HMAC verification strengthened with constant-time comparison

#### Medium Severity Fixes
- **Group Messaging**: Sender key validation and rotation improved
- **FFI Safety**: Double-free prevention and pointer validation added
- **Error Handling**: Sensitive information no longer exposed in error messages

### Added

#### Core Features
- `SecureContext` - Main entry point for all protocol operations
- `DoubleRatchetSession` - Improved session management with automatic rotation
- `RateLimiter` - Configurable rate limiting with burst support
- `SafetyNumber` - Identity verification with QR code support
- `GroupManager` - Efficient group messaging with sender keys

#### Cryptographic Improvements
- `CryptoHandler` - Unified encryption interface with ChaCha20-Poly1305
- `SecureRandom` - CSPRNG with entropy mixing and reseeding
- `HkdfKdf` - HKDF key derivation with iteration support
- `X3dhKdf` - X3DH shared secret derivation
- `constant_time_eq` - Constant-time comparison functions

#### Validation
- `validate_message()` - Message size and content validation
- `validate_key()` - Key strength and format validation
- `validate_session_id()` - Session ID validation
- `validate_password()` - Password strength validation
- `validate_timestamp()` - Timestamp validation with clock skew handling

### Changed

#### API Changes
- All error types now use `ProtocolError` enum
- Results use `ProtocolResult<T>` type alias
- Configuration moved to `Config` struct
- Session creation returns `SessionHandle` instead of raw session

#### Performance Improvements
- Reduced allocations in hot paths
- Improved cache locality
- Batch operations for group messaging
- Optimized key derivation

### Deprecated

- `sibna_protocol_v7` and `sibna_protocol_v8` modules (use `sibna_core` v9 instead)
- Direct access to session state (use provided methods)
- Manual key rotation (use automatic rotation)

### Removed

- Insecure JSON serialization for session state
- Weak key acceptance
- Unlimited skipped message keys storage
- Timing-sensitive comparison operations

### Fixed

#### Memory Safety
- Memory leaks in key storage
- Use-after-free in FFI bindings
- Double-free in buffer management
- Stack overflow in recursive operations

#### Cryptographic Issues
- Weak key detection
- Nonce reuse prevention
- Key derivation improvements
- Signature validation

#### Protocol Issues
- Replay attack prevention
- Out-of-order message handling
- Session state corruption
- Group membership synchronization

## [7.0.0] - 2023-XX-XX

### Added
- Initial release of Sibna Protocol
- X3DH key agreement
- Double Ratchet algorithm
- Basic group messaging
- FFI bindings

### Security
- Basic encryption with ChaCha20-Poly1305
- X25519 key exchange
- Ed25519 signatures

---

## Migration Guide

### From v7/v8 to v9

1. **Update Dependencies**
   ```toml
   [dependencies]
   sibna-core = "9.0.0"
   ```

2. **Update Configuration**
   ```rust
   // Old
   let config = Config::default_v7();
   
   // New
   let config = Config::default();
   ```

3. **Update Error Handling**
   ```rust
   // Old
   match result {
       Ok(val) => val,
       Err(e) => handle_error(e),
   }
   
   // New
   result.map_err(|e| {
       log_error(&e);
       e.into()
   })?;
   ```

4. **Update Session Management**
   ```rust
   // Old
   let session = ctx.get_session(id)?;
   
   // New
   let handle = ctx.create_session(id)?;
   let session = handle.session();
   ```

## Security Advisories

### Internal hardening (Fixed in 1.0.0)
**Severity**: Critical
**Description**: Memory leak in key storage could expose private keys
**Impact**: Private key exposure
**Fix**: All keys now properly zeroized on drop

### Internal hardening (Fixed in 1.0.0)
**Severity**: High
**Description**: Insecure serialization could leak session state
**Impact**: Session state exposure
**Fix**: Binary serialization with encryption

---

**Note**: This changelog only covers versions 7.0.0 and above. Earlier versions are not supported.
