# SIBNA PROTOCOL SDK CONSOLIDATION — TASK PROGRESS

## Environment

- Working dir: C:\Users\benso\Downloads\sibna-protc-main\sibna-protc-main
- NOT a git repository (no .git). No branches/commits/pushes performed.
- Python 3.13.5, cargo 1.92.0, rustc 1.92.0.
- pqcrypto 0.3.4 AND 1.0.0 both installed in system Python 3.13.

## SUMMARY OF WORK COMPLETED

### SDK Consolidation (DONE)

- Only `sdks/python/` remains (cpp/dart/flutter/go/java/javascript removed).
- Python SDK fully implemented: crypto.py, constants.py, errors.py, x3dh.py,
  ratchet.py, session.py, padding.py, envelope.py, group.py, safety_number.py,
  storage.py, client.py, __init__.py, py.typed, p2p.py
- pyproject.toml (setuptools), setup.py removed. sdist+wheel built.
- Clean venv install + smoke tests PASS.

### Version Sync (DONE)

- scripts/version_check.py — PASSES (protocol 10, package 3.0.1 all in sync).
- CI workflow: deleted SDK jobs removed; Python lint/mypy/conformance/
  version/build/install jobs added; Rust security jobs kept.

### Rust Core (INTACT)

- Rust core builds; 146 lib tests pass; sibna-server builds.
- cargo fmt/clippy/test pass.
- Security checks enabled in CI.

### Python SDK Tests (ALL PASS — 67 tests)

- Source tests: 64 pass (crypto, x3dh, ratchet, session, group, envelope,
  safety_number, padding, storage, version).
- ML-KEM-768 cross-implementation: 5 tests pass (Python decapsulates
  Rust-encapsulated, Python encapsulates→Rust decapsulates, X3DH hybrid
  initiator/responder agreement both directions).
- Interop vector reproduction tests pass.

### P2P Handshake (FIXED — WAS BROKEN)

Root cause analysis completed. Three categories of bugs were fixed:

1. **P2P X3DH identity mismatch** (critical — caused wrong shared secret):
   - Fix: P2P initiator sends `initiator_x25519_identity_pub` in StealthEnvelope
     (was missing entirely; Bob used Alice's ephemeral pub as identity pub).
   - Fix: Bob's `build_transcript` uses `identity_x25519.public_key` as
     `responder_x25519_pub` (was incorrectly using `signed_prekey.public_key`).
   - Fix: Initiator no longer passes `transcript_hash_ext` to x3dh_initiator
     (defaults to bytes(32), matching Rust/core behavior).

2. **Double Ratchet frame parsing** (fixed `ratchet_decrypt`):
   - `ratchet_encrypt` sends `frame = frame_header + ct_and_tag` where
     `frame_header = msg_num(8) + ts(8) + pad(8)` and `ct_and_tag = nonce(12) +
     ciphertext + tag(16)`. Returns `header(56) + frame`. This matches Rust
     `RatchetMessage::to_bytes()` + `Encryptor::encrypt_message()` output.
   - `ratchet_decrypt` correctly parses `frame = ciphertext[56:]` as
     `frame_header(24) + nonce(12) + ct_and_tag`, extracting
     `nonce = frame[24:36]` and `ct_and_tag = frame[36:]`.
   - `full_ad = associated_data + header(56) + frame_header(24)` matches Rust's
     `associated_data + RatchetHeader(56) + EncryptorHeader(24)`.
   - Key: `mk = HMAC-SHA256(chain_key, 0x01)` from `receiving_chain.next_message_key()`
     matches Rust's `RatchetKdf::kdf_ck(seed=0x01)`.
   - `chacha20_poly1305_decrypt` wrapped in try/except — raises
     `CryptoError("Decryption failed")` instead of raw `InvalidTag`.
   - `ratchet_decrypt` returns `envelope_payload` (was returning undefined
     `plaintext`).
   - `derive_handshake_key()` is NOT used in Double Ratchet — only `mk` from the
     chain key. P2P handshake uses `derive_handshake_key()` separately for its
     transport key. Correct separation of concerns.

### Phase 1B: Transactional Python Ratchet Decryption (DONE)

- Fixed `sdks/python/sibna/ratchet.py` `ratchet_decrypt()` to use transactional
  state cloning: all state mutations (root key, chain keys, DH keys, skipped
  keys, message counters) are performed on an isolated clone and committed only
  after ChaCha20-Poly1305 authentication succeeds.
- Added 5 regression tests:
  - `test_ratchet_decrypt_failure_no_state_mutation` — tampered ciphertext
    fails without mutating any state field; subsequent valid message decrypts
  - `test_ratchet_decrypt_failure_after_dh_ratchet` — failed auth after DH
    ratchet transition leaves state unchanged
  - `test_ratchet_skipped_key_not_consumed_on_failure` — skipped key not
    consumed on authentication failure; original valid message still decrypts
  - `test_ratchet_decrypt_success_commits_state` — successful in-order and
    out-of-order delivery advances state correctly
  - `test_multi_ratchet_roundtrip` — multiple DH ratchet transitions between
    Alice and Bob; all messages decrypt correctly
  - `test_multi_ratchet_tampered_then_valid` — tampered ciphertext fails,
    original valid ciphertext decrypts, state advances

### Phase 1C: Multi-Ratchet KDF Verification (DONE)

- Confirmed the suspected KDF asymmetry is BY DESIGN, not a defect:
  - Sending-side DH ratchet (`ratchet_encrypt`) uses one `kdf_rk` call:
    produces `(root_key, sending_chain_key)` from `new_local.dh(remote)`
  - Receiving-side DH ratchet (`_dh_ratchet_step`) uses two `kdf_rk` calls:
    KDF1: `(root_key, receiving_chain_key)` from `old_local.dh(new_remote)`;
    KDF2: `(root_key, sending_chain_key)` from `new_local.dh(new_remote)`
  - DH commutativity ensures both sides derive identical keys
  - Multi-ratchet roundtrip test confirms all messages decrypt across
    ratchet boundaries

### Phase 1D: X3DH Identity Authentication and Specification Consistency (DONE)

- Fixed `core/src/handshake/mod.rs` `PreKeyBundle::validate()`:
  - SPK signature now verified over `"SibnaSignedPreKey_v3" || signed_prekey`
  - Previously verified over `signed_prekey` alone (no domain prefix)
  - Now consistent with `perform_handshake()` and Python `verify_spk_signature()`
  - Updated `test_prekey_bundle_validation` to sign with domain prefix
- Updated `PROTOCOL_SPECIFICATION.md` §2.3:
  - PQ hybrid KDF input order corrected from `ss_kem || dh1 || dh2 || dh3 || dh4`
    to `dh1 || dh2 || dh3 || dh4 || ss_kem` (matches verified Rust and Python
    implementations)
  - Classical KDF ordering unchanged (already correct)

### Final Validation (ALL PASS)

- 146/146 Rust lib tests pass.
- 67/67 Python tests pass (70 collected, 3 interop tests excluded by `-m interop`
  marker, run via `run_interop.ps1`).
- Rust interop tests: 4/4 pass (2 positive + 2 negative).
- Python multi-ratchet tests: 2/2 pass.
- Rust prekey tests: 7/7 pass.
- Rust X3DH tests: 5/5 pass.
- black --check: PASS.
- mypy: PASS (no issues in 14 source files).
- version_check.py: PASS.
- pyproject build: sdist + wheel succeed.
- Clean venv install + smoke test: PASS.
- No Python cache/bytecode artifacts remain in working tree.
- No tracked SDK references remain (only sdks/python/).

### Unified Interop Test Runner

- `run_interop.ps1` at repo root — executes the full cross-implementation
  workflow:
  1. Clean up stale temp fixtures
  2. Python generates fresh ciphertexts (`-m interop`)
  3. Rust decrypts/verifies Python ciphertexts + negative tests + writes Rust
     ciphertexts
  4. Python decrypts/verifies Rust ciphertexts (`-m interop`)
  5. Clean up temp fixtures
- Subprocess failures propagate as nonzero exit codes.
- Python interop tests marked `@pytest.mark.interop` and excluded from default
  suite via `addopts = "-m \"not interop\""` in pyproject.toml, so the full
  Python SDK suite runs independently without fixture dependencies.
- Missing fixtures cause hard assertion failures (no silent skip).

### Cross-Implementation Audit (WIRE FORMAT)

- `ratchet_encrypt`/`ratchet_decrypt` wire format matches Rust core exactly:
  header(56) + frame_header(24) + nonce(12) + ciphertext + tag(16).
- Associated data matches: `caller_ad + header(56) + frame_header(24)`.
- Key derivation matches: `HMAC-SHA256(chain_key, 0x01)` for message key.
- `derive_handshake_key()` is NOT used in Double Ratchet — only in P2P
  transport.
- **VERIFIED BY CROSS-SDK ROUND-TRIP TESTS** (not just code analysis):
  - Direction A (Python → Rust): Python encrypts → Rust decrypts — PASS
  - Direction B (Rust → Python): Rust encrypts → Python decrypts — PASS
  - Negative case 1 (tampered ciphertext): PASS (rejects with cryptographic error)
  - Negative case 2 (wrong associated data): PASS (rejects with cryptographic error)
- Coordination: Python writes `%TEMP%\sibna_py_ratchet_ct.json` → Rust
  reads/decrypts/writes `%TEMP%\sibna_rust_ratchet_ct.json` → Python
  reads/decrypts. Temp fixtures cleaned up after test cycles. Missing fixtures
  cause hard assertion failures (no silent skip).

### Remaining Work

- Gap 3: Rust integration-test coverage (test_mdns_discovery hangs on Windows).
- Gap 5: SDK inventory confirmed — Python only official SDK.
- Server health endpoint returns "3.0.0" while all other components report
  3.0.1 — potential client-side version mismatch logic issue.

### Blockers

- None currently blocking. Windows has no `head`/`grep` Unix tools — use
  PowerShell Select-Object/Get-ChildItem.
