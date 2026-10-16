# Sibna Repository — Analysis Summary

*Analysis phase only — no source files modified.*

## 1. What exists today?

### Repository layout

- `core/` — Rust protocol core (X3DH, Double Ratchet, groups, padding, storage, keystore, P2P transport)
- `server/` — Axum-based relay server (REST + WebSocket)
- `sdks/python/` — Sole official Python SDK (pure Python cryptography + relay client, no FFI/native dependency)
- `tests/` — Shared interop + security tests (cross-SDK padding vectors, attack tests)
- `scripts/` — Version consistency check (`scripts/version_check.py`)
- `.github/workflows/` — CI: fmt, clippy, tests, audits, Python conformance
- `PROTOCOL_SPECIFICATION.md` — Normative wire-format specification
- `SECURITY.md` — Security policy & disclosure
- `THREAT_MODEL.md` — Attacker model & residual risks
- `CHANGELOG.md` — Release history
- `CONTRIBUTING.md` — Contribution rules
- `LICENSE` — Apache-2.0 OR MIT (dual)

### Version

| Component | Version |
|-----------|---------|
| Protocol specification | v3.0.2 |
| Rust workspace (Cargo.toml) | 3.0.2 |
| Python SDK (pyproject.toml / __init__.py) | 3.0.2 |
| Protocol wire VERSION_NUMBER | 10 |
| MIN_COMPATIBLE_VERSION | 9 |

Versions are kept in sync by `scripts/version_check.py`, which runs as a mandatory CI gate.

### Rust core (`sibna-core`)

The Rust core is a fully functional cryptography implementation providing:

- **X3DH handshake** (fully implemented):
  - Ed25519 identity keys + X25519 key agreement
  - Signed prekeys (SPK) with Ed25519 signature verification before DH computation
  - One-time prekeys (OPK) as optional 4th DH component
  - BLAKE3 transcript hash + HKDF-SHA256 "SibnaX3DH_TranscriptBind_v3" transcript binding
  - Hybrid PQC support (ML-KEM-768 / Kyber) via `pqc` feature flag
  - Session key derivation via HKDF with "SibnaX3DH_v3" info string
  - Constant-time DH validation, low-order point rejection

- **Double Ratchet** (fully implemented):
  - Symmetric ratchet: HMAC-SHA256(chain_key, 0x01) → message_key; HMAC-SHA256(chain_key, 0x02) → next_chain_key
  - DH ratchet: X25519 DH output → HKDF("SibnaRatchet_v3") → new root_key + chain_key (single 64-byte expand)
  - ChaCha20-Poly1305 AEAD for message encryption
  - Ratchet header: dh_public(32) || message_number(8) || previous_chain_length(8) || timestamp(8)
  - Header encryption (v3.1): encrypted header via ChaCha20-Poly1305 under header_key derived from chain key
  - Replay protection via seen_numbers HashMap with time-bounded eviction (86400s cutoff)
  - Skipped message key cache: up to 2000 out-of-order keys, each expires after 86400s, single-use
  - Empty plaintext allowed for cover/dummy traffic
  - Session persistence via serialize_state/deserialize_state (with dh_keys re-hydration on load)
  - Cover traffic: dummy messages with exponential inter-packet delays, Poisson process, mean 5s

- **Group messaging / Sender Keys** (fully implemented):
  - SenderKey chain: HKDF(chain_key, "SibnaGroupMessageKey_v3") → message_key; HKDF(chain_key, "SibnaGroupChainKey_v3") → next_chain_key
  - Key distribution: X25519 DH + HKDF("SibnaGroupKeyDistribute_v3") + ChaCha20-Poly1305 encryption of sender key
  - SenderKeyMessage format: group_id(32) || sender_public_key(32) || key_id(4) || encrypted_key(length-prefixed) || signature(64)
  - GroupSession encrypt/decrypt, key rotation, member management

- **Safety numbers** (fully implemented):
  - 80-digit fingerprint from SHA-512(0x01 || "SIBNA_SAFETY_NUMBER_V1" || sorted_keys)
  - First 32 bytes → 16 groups of 5 digits
  - QR code format: version(1) + "SB1"(3) + fingerprint(32) = 36 bytes
  - Constant-time comparison via HMAC-SHA256

- **Storage / Persistence** (fully implemented):
  - Argon2id-encrypted keystore with salt file (b"SIBNA_SALT_V1" header)
  - bincode serialization (legacy format) with HMAC-protected manifest
  - Key rotation: SPK rotated every 86400s (default 24h), OPK replenishment below threshold
  - Disk I/O: atomic write (temp + rename), size limits (10MB max keystore)

- **P2P transport** (conditional feature `p2p`):
  - TCP length-prefixed transport with SOCKS5 proxy support
  - mDNS discovery (optional)
  - STUN/ICE-like NAT traversal infrastructure
  - P2P handshake: 4-message exchange (Hello → Bundle → Envelope → Ok) with stealth bundles
  - Identity verification: expected_peer_identity check against Ed25519 key
  - Single ephemeral key shared between transport and X3DH

- **Cryptographic primitives** (all via well-audited libraries):
  - X25519 DH with low-order point rejection (8 known points)
  - Ed25519 signing & verification
  - ChaCha20-Poly1305 AEAD (nonce, ciphertext, tag)
  - HKDF-SHA256 (extract-then-expand)
  - BLAKE3 for transcript hashing
  - SHA-256 and SHA-512
  - HMAC-SHA256
  - Constant-time comparison (subtle)
  - Secure zeroization throughout

- **Rate limiting** (hybrid IP + identity):
  - Token bucket per operation, per IP, per identity
  - Global RPS limits + per-identity buckets
  - Prekey upload/fetch/auth limited separately

- **Validation** comprehensive layer:
  - Input length limits, null byte checks, repeating pattern detection
  - Key validation (not all zeros, not repeating patterns)
  - Public key validation (low-order point rejection)
  - Associated data length limits (256 bytes max)
  - Timestamp validation (future ±30s, expired >5m, max age 24h)

### Python SDK (`sdks/python`)

The Python SDK is a pure-Python implementation of the full Sibna Protocol stack:

**Implemented:**
- Ed25519 identity keypair generation (`Identity` class)
- Ed25519 sign/verify (`Identity.sign`, `verify_signed_envelope`)
- Sealed-envelope message format (`make_signed_envelope`, `verify_signed_envelope`) — sign + payload metadata
- Block-aligned payload padding (`pad_payload`, `unpad_payload`) — 1024-byte blocks, metadata resistance
- Sync HTTP client (`SibnaClient`) — REST API, prekey management, inbox polling
- Async WebSocket client (`AsyncSibnaClient`) — real-time relay, ACK on received messages
- TLS certificate pinning (PEM file)
- Fan-out to multiple devices (`send_message_multi`, `send_multi`)
- Offline inbox polling with signature verification
- X3DH handshake (initiator/responder, SPK signature verification)
- Double Ratchet sessions (Rust wire-compatible)
- Sender-key groups, key distribution, signed group messages
- Safety numbers (80 digits)
- ML-KEM-768 hybrid KEM (FIPS 203)
- Encrypted storage with rollback protection
- Relay HTTP + WebSocket client (JWT auth)

**Python SDK crypto primitives:**
- `crypto.py` provides: X25519KeyPair with dh() method, Ed25519KeyPair, ChaCha20-Poly1305 encrypt/decrypt, HKDF-SHA256, HMAC-SHA256, SHA-256/SHA-512, BLAKE3 (mandatory), random_bytes

**Python SDK module structure:**
- `sibna/__init__.py` — Public API + version
- `sibna/client.py` — main client (sync + async)
- `sibna/crypto.py` — standalone cryptographic primitives
- `sibna/x3dh.py` — X3DH key agreement functions (PreKeyBundle, X3DHResult, x3dh_initiator, x3dh_responder)
- `sibna/ratchet.py` — Double Ratchet implementation (ChainKey, DoubleRatchet)
- `sibna/session.py` — Session combining X3DH + Double Ratchet (high-level API)
- `sibna/group.py` — GroupSession (Sender Keys protocol)
- `sibna/safety_number.py` — SafetyNumber 80-digit fingerprints
- `sibna/envelope.py` — Signed envelopes (canonical length-prefixed form)
- `sibna/padding.py` — Block-aligned metadata-resistant padding
- `sibna/storage.py` — Encrypted storage + rollback protection
- `sibna/constants.py` — Protocol versions, wire formats, KDF strings
- `sibna/errors.py` — Typed exceptions
- `sibna/p2p.py` — P2P transport and handshake

### Version information

| Component | Version |
|-----------|---------|
| Protocol specification | v3.0.2 |
| Rust core (CARGO_PKG_VERSION) | 3.0.2 |
| Python SDK (__init__.py __version__) | 3.0.2 |
| Python SDK (pyproject.toml version) | 3.0.2 |
| Protocol wire VERSION_NUMBER | 10 |
| MIN_COMPATIBLE_VERSION | 9 |

## 2. Existing tests

### Rust core tests (`core/tests/`)

- **integration.rs**: Basic ratchet roundtrips, replay protection, forward secrecy, out-of-order delivery, group create, identity generation, session requires identity
- **proptest_properties.rs**: Property-based tests for crypto encrypt/decrypt roundtrip, wrong AD rejection, tampered ciphertext rejection, empty plaintext allowance (cover traffic), padding roundtrip (standard + 64KB), ratchet encrypt/decrypt roundtrip, replay detection, multiple messages order-independent, serialize/deserialize roundtrip with post-restore encrypt, skip keys bounds
- **test_python_interop.rs**: Cross-implementation Double Ratchet tests (Python→Rust and Rust→Python directions, plus negative tests for tampered ciphertext and wrong associated data)
- **gen_interop_vectors.rs**: Generates committed Rust interop test vectors
- **offensive_test.rs / advanced_offensive_test.rs**: Offensive/security tests (weekly CI)
- **attack_tests.rs**: 12 attack vectors against the full system (requires running server, weekly CI)
- **proptest_properties.rs**: Property-based tests
- **statistical_timing_test.rs**: Statistical timing tests
- **debug_x3dh.rs**: X3DH debug tests

### Python SDK tests (`sdks/python/tests/`)

- **test_envelope.py**: Envelope signing/verification tests
- **test_group.py**: Group messaging tests
- **test_interop_vectors.py**: Cross-SDK padding compatibility tests
- **test_pq_kem_interop.py**: ML-KEM-768 cross-implementation interop tests
- **test_ratchet.py**: Double Ratchet conformance tests (roundtrip, chain advances, out-of-order, replay, tampered ciphertext, timestamp boundaries, message-number limits, Rust fixture decryption, X3DH shared secret, PQ hybrid, multi-ratchet)
- **test_ratchet_python_to_rust_interop.py**: Cross-implementation Rust↔Python Double Ratchet interop tests (marked `@pytest.mark.interop`, run via `run_interop.ps1`)
- **test_sibna.py**: SDK smoke tests
- **test_storage.py**: Encrypted storage tests
- **test_version.py**: Version consistency tests

### Cross-SDK test vectors (`tests/cross_sdk/`)

- **padding_vectors.json**: 5 padding test vectors
- **test_cross_sdk_padding.py**: Validates Python pad/unpad against Rust hand-built fixtures

### CI (`.github/workflows/ci.yml`)

Fast checks (every push/PR): fmt, clippy, test-core, test-proptest, build-verify, sdk-python, audit-deny, audit-vulnerabilities, build-native.

Weekly checks: test-offensive, test-attack, dependency-check, fuzz, kani, miri.

## 3. Interoperability risks between Rust and Python

| Risk | Severity | Description |
|------|----------|-------------|
| Padding format mismatch | High | Python `pad_payload` must exactly match Rust `pad_message` — cross-SDK test validates this but small drifts possible |
| X3DH transcript hash mismatch | High | Transcript hash order of public keys + device IDs must exactly match Rust |
| Double Ratchet state synchronization | High | Session state (root_key, chain keys, DH keys) must be bit-for-bit compatible |
| Safety number mismatch | Medium | Algorithm exists in both but not tested for cross-SDK consistency |
| Cover traffic behavior | Medium | Python doesn't implement cover traffic; if implemented must match Rust's Poisson process |

## 4. Security risks / architectural problems

| Risk | Category | Description |
|------|----------|-------------|
| Python SDK gives false E2EE sense | Security | Users may think Python SDK provides E2EE because it has "cryptography" in name — but it DOES implement full E2EE |
| Server health says "3.0.0" | Configuration | Version mismatch between server and clients could cause compatibility issues |
| Cover traffic requires `p2p` feature flag | Documentation | README says cover traffic works but it requires `p2p` feature and active relay client — users may be confused |
| SPK signature verification is mandatory in core | Security | Rust core rejects handshakes without SPK signature verification; Python enforces the same |
| dh_local never persisted (intentional) | Design | Private X25519 scalars are never written to disk — after load, dh_local is None and next ratchet step generates fresh pair. This is correct per protocol but means session restore needs special handling. |
| P2P expected_peer_identity guards MITM | Security | When set, rejects any peer whose identity key doesn't match. When None, relies on safety number interactive verification. |

## 5. Recommended architecture

### Tier 1: Rust Core (protocol implementation)

Keep as the single source of truth for all cryptographic protocol operations:
- X3DH handshake
- Double Ratchet (symmetric + DH ratchet)
- Group messaging (sender keys)
- Safety numbers
- Key storage persistence
- P2P transport
- All cryptographic primitives with zeroization

### Tier 2: Python SDK (full protocol stack)

Maintain as a complete, standalone protocol implementation:
- X3DH handshake (initiator/responder, SPK validation)
- Double Ratchet session management
- Group messaging (sender keys)
- Safety numbers
- Encrypted storage
- Signed envelopes
- Block-aligned padding
- Relay HTTP + WebSocket client
- Standalone crypto primitives (X25519 DH, ChaCha20-Poly1305, HKDF, BLAKE3, ML-KEM-768)

## 6. Biggest risks

1. **Padding format drift between SDKs** — cross-SDK test vectors exist but need ongoing validation
2. **Version confusion** - server health endpoint returns "3.0.0" while everything else says 3.0.2
3. **Interoperability if Python ever diverges from Rust core** — must exactly match Rust core KDF parameters, transcript hashes, wire formats
4. **No independent security audit** — protocol and implementations have not been formally reviewed

## 7. What should not be done

- Do NOT delete or reduce the Rust core — it's the security foundation
- Do NOT implement full X3DH/Double Ratchet in Python without exact matching of all Rust core parameters
- Do NOT ignore the version inconsistencies between server (3.0.0) and clients (3.0.2)
