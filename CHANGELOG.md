# Changelog — Sibna Protocol

All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased] — Documentation Transparency Pass

### Fixed
- `core/src/p2p/handshake.rs:55` — corrected stale "warn-only mode" doc-comment on `P2pHandshakeConfig::expected_peer_identity` that contradicted the post-PATCH-17 behaviour (the field is now mandatory; `None` rejects the connection). A reader relying on the old comment would have assumed they could leave the field unset and merely receive a warning.
- `audit/README.md:58` — reconciled the `fips203` version note: the actually pinned version is `0.4.3` (per `Cargo.toml:53` and `audit/VERIFICATION.md:152`); the `0.5.0` reference in `audit/AUDIT_REPORT.md:168,273` is a target upgrade that was never applied.
- `audit/verification_report.md:52` — replaced the unqualified "production-ready" conclusion with a "hardened and pre-audit ready" status that cites `audit/EXECUTIVE_BRIEF.md` as the authoritative verdict and lists the four residual risk dimensions the EXECUTIVE_BRIEF names.

### Added
- `README.md` — new "Network anonymity features" section listing Tor (SOCKS5) and Cover Traffic with explicit limitations (mDNS cleartext on LAN, requires the `p2p` feature flag, only the Rust core exposes SOCKS5 configuration, etc.). Makes the threat model in `docs/THREAT_MODEL.md` discoverable from the README's table of contents.
- `core/src/ffi/mod.rs:100` — `ByteBuffer::to_vec` now takes `&mut self` and nulls the inner pointer after transferring ownership to a `Vec<u8>`. The previous `&self` signature was a latent double-free: any caller doing `vec = buf.to_vec(); buf.free();` would crash with `STATUS_HEAP_CORRUPTION` on Windows. All FFI tests now pass (202/202 Rust tests green).
- `core/src/ffi/mod.rs:999` — `test_byte_buffer` now declares `mut buffer` so the test compiles. The previous `let buffer = ...` failed `cargo test` with `E0596`.

---

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
