# Changelog — Sibna Protocol

All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [3.0.2] — 2026-10-17 (Security, Correctness, Interoperability)

Release tag: `v3.0.2`. Wire protocol version remains `10`.

### Security Fixes — HIGH

- **Decompression allocation DoS (core/src/iot.rs)** — `decompress()` only enforced the 20 MiB declared-size limit when `data.len() > 4`, letting a 4-byte attacker-controlled header force an unbounded allocation (decompression bomb). **Fix:** reject inputs shorter than 4 bytes and enforce the declared-size cap for every full 4-byte header before any allocation. Added regression tests for short headers, empty/truncated/malformed input, oversized declared length (at/above/below the 20 MiB boundary), and invalid MQTT compression payloads.

- **Delayed-message rejection by client age check (core/src/ratchet/mod.rs, sdks/python/sibna/ratchet.py)** — both Rust and Python rejected any ratchet message older than 24 h by wall-clock age, breaking legitimate store-and-forward/offline delivery (server queues up to 7 days). **Fix:** removed the past-age rejection; keep `timestamp == 0` and future-timestamp (> now + 300 s) rejection. Expiration is enforced server-side by the queue TTL; replay is prevented by per-session message-number tracking. The previously-failing `test_decrypt_rust_fixture_ciphertexts` now passes.

### Correctness

- **Interop runner temp-path mismatch (run_interop.sh, run_interop.ps1)** — `run_interop.sh` created two separate `mktemp -d` directories that never matched the fixed OS temp paths used by the Python and Rust tests, so the runner always failed its artifact checks. **Fix:** both runners now use the OS temp dir (`${TMPDIR:-/tmp}` / `$env:TEMP`) consistent with the tests, stop on first failure, propagate exit codes, validate artifacts before consuming them, and clean up safely on exit. Genuine Rust↔Python ratchet interop verified in both directions.

- **Rust test `unused_mut` warnings** — removed unneeded `mut` bindings in `core/tests/test_python_interop.rs` so the crate builds cleanly under `RUSTFLAGS=-D warnings`.

- **Stale X3DH ordering note (sdks/python/sibna/x3dh.py)** — corrected a comment that claimed the PQ hybrid shared-secret ordering differed from the specification; spec §2.3, Rust, and Python all concatenate `dh1||dh2||dh3||dh4||ss_kem`.

### Release Engineering

- Bumped package/wire-consistent version to `3.0.2` across `Cargo.toml`, `pyproject.toml`, `sibna/__init__.py`, `sibna/constants.py`, and the server health endpoint. Wire protocol version remains `10`.

## [Unreleased] — v3.1.0 Security & Interop Fixes

### Security Fixes — CRITICAL

- **Python Padding extra_blocks (sdks/python)** — `pad_payload` drew `extra_blocks` from [0,1] instead of [0,7], undermining SIBNA-2026-018 metadata resistance. **Fix:** `extra_blocks = secrets.randbelow(cap + 1)` with cap = min(7, max_blocks_for_budget). Added size distribution + wire format tests.

- **Python WebSocket JWT Leak (sdks/python)** — Async WebSocket client appended JWT to query string (`/ws?token=...`), leaking in access logs, browser history, Referer. **Fix:** token now sent via `Authorization: Bearer <jwt>` header in `ws_connect()`.

### Documentation

- `CHANGELOG.md` — this entry
- `README.md` — repository layout and component descriptions updated
- `PROTOCOL_SPECIFICATION.md` — PQ hybrid KDF input ordering corrected to match implementation (`dh1 || dh2 || dh3 || dh4 || ss_kem`); Signed PreKey signature domain prefix (`"SibnaSignedPreKey_v3"`) made consistent across Rust `PreKeyBundle::validate()` and `perform_handshake()`
- `core/src/handshake/mod.rs:55` — stale comment corrected

### Breaking Changes

- **Python SDK**: WebSocket handshake now uses `Authorization: Bearer` header instead of query string; server must be updated.

---

## [3.0.1] — 2026-06-04 (Security Hardening)

### Fixed

- **Cover traffic delivery**: `send_dummy_to_relay` now actually transmits encrypted dummy packets via the relay server instead of silently discarding them.
- **Relay message delivery**: `send_via_relay` now constructs and sends signed envelopes via `RelayClient` instead of only encrypting without transmission.
- **Tor/SOCKS5 proxy wiring**: `P2pNode::connect` now routes through `connect_with_optional_proxy` using the configured proxy address. `HybridRouter` initializes `RelayClient` with proxy support from `Config::proxy_url`.
- **Documentation inconsistencies**: Updated references across documentation files to reflect the completed migration to redb.

### Changed

- **RelayClient**: Added `send_envelope` method for transmitting signed JSON envelopes to the relay server.
- **HybridRouter**: Added `relay_client` field and `init_relay_from_config` method for relay integration.
- **Dead code removal**: Removed unused `Socks5Config` and `TlsConfig` structs from `transport/mod.rs`.

---

## [3.0.0] — 2026-04-06 (Ultimate Upgrade)

### Security Fixes — CRITICAL

- **Timing Oracle Fix**: Replaced string comparisons with `subtle::ConstantTimeEq` for challenge authentication.
- **Transcript Binding**: Included `device_id_A` and `device_id_B` in the X3DH transcript hash for absolute session binding.
- **KDF Hardening**: Corrected HKDF salt usage (salt=T) and updated ratchet labels to `v3.0.0`.
- **Padding Unification**: Unified all padding implementations to use the hardened "Noise Prefix" format.
- **Documentation Overhaul**: Removed all unverified security claims (Kani, Fuzzing) to ensure technical honesty.

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
