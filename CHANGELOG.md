# Changelog — Sibna Protocol

All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased] — v3.1.0 Security & Interop Fixes (2026-06-07)

### Security Fixes — CRITICAL

- **Java X3DH Responder (sdks/java)** — The X3DH responder silently derived a different shared secret from the initiator because `X3DHHandshake.respond()` had no access to the local signed prekey and used the identity key for all three DH operations. Result: `DH1 = IK_B*IK_A` (should be `SPK_B*IK_A`), `DH2 = IK_B*EK_A` (correct), `DH3 = IK_B*EK_A` (should be `SPK_B*EK_A` and equals DH2). **Fix:** new `PreKeyPair` class wrapping the local signed prekey; `X3DHHandshake` constructor takes it; `respond()` now uses SPK for DH1/DH3. `SibnaClient.acceptSession()` signature extended with required `PreKeyPair` parameter. Added `testX3DH_responderSharedSecretMatchesInitiator` proving cross-SDK shared secret equality.

- **Go Padding Wire Format (sdks/go)** — `PadPayload`/`UnpadPayload` used a completely different on-wire format (`[indicator(1)|pad_len(2,BE)|plaintext|padding]`) than the Rust core (`[prefix_len(1)|prefix_noise(1..8)|plaintext|padding|pad_len(2,LE)]`), used BIG-endian pad_len, and produced deterministic block sizes. **Fix:** rewritten to match core/src/crypto/padding.rs exactly: prefix_len ∈ [1,8], prefix noise, LE pad_len, extra_blocks ∈ [0,7] per SIBNA-2026-018. Added 3 regression tests.

- **Python Padding extra_blocks (sdks/python)** — `pad_payload` drew `extra_blocks` from [0,1] instead of [0,7], undermining SIBNA-2026-018 metadata resistance. **Fix:** `extra_blocks = secrets.randbelow(cap + 1)` with cap = min(7, max_blocks_for_budget). Added size distribution + wire format tests.

- **JavaScript Math.random() + extra_blocks (sdks/javascript)** — `padPayload` used `Math.random()` (non-crypto) for `prefixLen` and `extraBlocks`, and capped `extraBlocks` at 0..1. **Fix:** uses `crypto.getRandomValues()` for both; `extraBlocks` ∈ [0,7] with budget cap. Added 3 tests mirroring Python/Go.

- **Flutter/Dart FFI ABI Mismatch (sdks/flutter, sdks/dart)** — `sibna_session_encrypt/decrypt` native signature is 8 args (`context, session_id, session_id_len, plaintext, plaintext_len, ad, ad_len, out_buf`); Flutter binding declared 6 args (missing `ad, ad_len`). Session code passed session handle as context, plaintext as session_id. **Fix:** binding updated to 8 args; `SibnaSession` stores parent context and passes it correctly; Dart bindings added for session_encrypt/decrypt, group_create/destroy, identity_generate/destroy; stub `UnimplementedError` methods replaced with FFI calls. Added helpers `_copyToNative`, `_readAndFreeBuffer`.

- **C++ SafetyNumber (sdks/cpp)** — Missing domain separator "SIBNA_SAFETY_NUMBER_V1" in hash input; 60 hex digits vs Rust's 80 decimal digits; different grouping. Cross-SDK verification was broken. **Fix:** domain separator added; output format matches Rust (80 decimal digits, 16 groups of 5, space every 3 groups); `parse()` and `similarity()` updated.

- **Python WebSocket JWT Leak (sdks/python)** — Async WebSocket client appended JWT to query string (`/ws?token=...`), leaking in access logs, browser history, Referer. **Fix:** token now sent via `Authorization: Bearer <jwt>` header in `ws_connect()`.

### SDK Completeness

- **Dart/Flutter** — `sibna_session_encrypt/decrypt`, `sibna_group_create/destroy`, `sibna_identity_generate/destroy` now bound and implemented. No more `UnimplementedError` stubs.
- **C++ Crypto::pad/unpad** — Previously declared but missing; test_crypto.cpp would not link. Now implemented matching Rust core format exactly.

### CI & Testing

- Added CI jobs for **Java (Maven)**, **JavaScript (Jest/ts-jest)**, **Dart (dart test)**, **C++ (CMake + Catch2)**. Previously only Python and Go ran in CI.
- Added `tests/cross_sdk/padding_vectors.json` with canonical vectors and `tests/cross_sdk/test_cross_sdk_padding.py` validating Python against them + a hand-built Rust fixture.

### Documentation

- `CHANGELOG.md` — this entry
- `README.md` — "Network anonymity features" section added
- `audit/README.md` — fips203 version pinned to 0.4.3 (reconciled with Cargo.toml)
- `audit/verification_report.md` — "production-ready" qualified to "hardened and pre-audit ready"
- `core/src/p2p/handshake.rs:55` — stale "warn-only mode" comment corrected

### Breaking Changes

- **Java SDK**: `SibnaClient.acceptSession()` signature changed (added required `PreKeyPair localSignedPrekey`).
- **Go SDK**: Wire format changed — stored padded payloads must be re-padded.
- **Python SDK**: WebSocket handshake now uses `Authorization: Bearer` header instead of query string; server must be updated.
- **Flutter/Dart SDK**: `SibnaSession` constructor now requires parent context; encrypt/decrypt signatures unchanged but now work correctly.
- **C++ SDK**: SafetyNumber output format changed from 60 hex digits to 80 decimal digits.

---

## [Unreleased] — Documentation Transparency Pass

## [3.0.1] — 2026-06-04 (Security Hardening)

### Fixed
- **C++ SDK double-free**: `create_session` and `create_group` returned `unique_ptr` with default deleter on pointers still owned by internal maps. Now uses null deleter for non-owning pointers.
- **C++ SDK BIO_new NULL checks**: `Utils::bytes_to_base64` and `Utils::base64_to_bytes` now validate `BIO_new()` return values before use.
- **Cover traffic delivery**: `send_dummy_to_relay` now actually transmits encrypted dummy packets via the relay server instead of silently discarding them.
- **Relay message delivery**: `send_via_relay` now constructs and sends signed envelopes via `RelayClient` instead of only encrypting without transmission.
- **Tor/SOCKS5 proxy wiring**: `P2pNode::connect` now routes through `connect_with_optional_proxy` using the configured proxy address. `HybridRouter` initializes `RelayClient` with proxy support from `Config::proxy_url`.
- **Documentation inconsistencies**: Updated sled references across 8 documentation files to reflect the completed migration to redb.

### Changed
- **RelayClient**: Added `send_envelope` method for transmitting signed JSON envelopes to the relay server.
- **HybridRouter**: Added `relay_client` field and `init_relay_from_config` method for relay integration.
- **Dead code removal**: Removed unused `Socks5Config` and `TlsConfig` structs from `transport/mod.rs`.

### Added
- **C++ SDK test suite**: 7 test files covering identity, crypto, session, context, group, safety number, and utility operations (37 test cases total).
- **Test infrastructure**: CMakeLists.txt for C++ tests with Catch2 framework integration.

---

## [3.0.0] — 2026-04-06 (Ultimate Upgrade)

### Security Fixes — CRITICAL
- **Timing Oracle Fix**: Replaced string comparisons with `subtle::ConstantTimeEq` for challenge authentication.
- **Transcript Binding**: Included `device_id_A` and `device_id_B` in the X3DH transcript hash for absolute session binding.
- **KDF Hardening**: Corrected HKDF salt usage (salt=T) and updated ratchet labels to `v3.0.0`.
- **Padding Unification**: Unified all padding implementations to use the hardened "Noise Prefix" format.
- **Documentation Overhaul**: Removed all unverified security claims (Kani, Fuzzing) to ensure technical honesty ("مامن قول و فعل").

### Major Features
- **Delivery ACKs (Zero Message Loss)**: Server-side queueing algorithm with Store-and-Forward policy.
- **Last Resort PreKey**: Prevents One-Time key starvation for offline nodes.
- **WebRTC Fast-path**: Engineered signaling wrappers for audio/video calls.
- **Hybrid Router**: Seamless fallback between P2P discovery and relay routing.

### Maintenance
- Deleted leaked PowerShell output (`check_out.txt`).
- Standardized project version to `v3.0.1` across all crates and documentation.

---

## [0.9.0] — 2024-03-20
- Post-Quantum integration (ML-KEM-768).
- Finalized foundational P2P mDNS Discovery routing paths.

## [0.8.0] — 2024-01-15
- Implementation of the foundational cryptographic Double Ratchet.
- Implementation of Classic X3DH key negotiation.
