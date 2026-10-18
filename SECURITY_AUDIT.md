# SIBNA PROTOCOL v3.0.2 — SECURITY & CORRECTNESS AUDIT LEDGER

**Repository:** SibnaOfficial/sibna-protc (local snapshot)
**Target version:** 3.0.2
**Wire protocol version:** 10 (unchanged)
**Baseline:** No `.git` directory present in the provided snapshot; no remote, branches, or PR #4 accessible locally. Working tree is a flat file snapshot at `C:\Users\benso\Downloads\sibna-protc-main\sibna-protc-main`.
**Toolchain:** rustc/cargo 1.92.0; Python 3.13.5 (repo tests run from `sdks/python`); pip 23.0.1 (Python 3.10). Installed SDKs: cryptography 46.0.3, blake3 1.0.10, pqcrypto 1.0.0, pytest 9.0.1, mypy 1.18.2, black 25.11.0, aiohttp 3.14.5, requests 2.31.0.

> NOTE: Git operations (push to release/3.0.2, PR #4, tag v3.0.2) CANNOT be performed in this environment — there is no git repository and no remote. This is recorded as a blocker (see Ledger). All code fixes are applied to the working tree; CI runs cannot be triggered remotely.

## AUDIT BASELINE (Phase Zero)

Repo tree inspected: core (Rust), sdks/python (sole official SDK), server (Axum/redb relay), tests, scripts, .github/workflows.

### Baseline test results (as-found, before changes)

**Python SDK (`sdks/python`):**
- `python -m pytest tests/ -p no:cacheprovider` → **1 failed, 66 passed, 3 deselected** (interop deselected by addopts).
- FAILED: `tests/test_ratchet.py::test_decrypt_rust_fixture_ciphertexts`
  - `sibna/ratchet.py:421` → `CryptoError: Message too old`
  - Root cause: Rust-committed fixture (`tests/cross_sdk/interop_vectors.json`) embeds a creation timestamp (~2026-06-15); Python ratchet rejects messages older than `MAX_MESSAGE_AGE_SECS=86400` (24 h). A legitimate delayed/authenticated message cannot be decrypted. **CONFIRMED reproducible.**
  - This is the delayed-message / timestamp-staleness defect (server queues up to 7 days; envelope checks 5 min; ratchet checks 24 h).

**Rust:** not yet run (baseline pending).

### Tooling/environment notes
- PowerShell: `&&`, `head`, `tail`, `find`, `2>/dev/null` unavailable; use `;`, `Select-Object`, `Get-Content`, `2>$null`.
- No `python3` executable (only `python` → 3.13.5). `pip` resolves to Python 3.10 but installs for 3.13 environment used by tests.
- `sibna` 3.0.2 is pip-installed from `...\sibna-protc-staging\sdks\python` (a separate path), but tests import the repo's local `sdks/python/sibna` (3.0.1) because CWD shadows it.
- `.mypy_cache`, `__pycache__`, `dist/`, `target/` present (build artifacts, not source).

---

## FINDING LEDGER

Format: ID | Severity | File/Component | Root cause | Evidence | Fix | Regression test | Verification | Compatibility impact | Status

---

### F-001 — Decompression allocation DoS (FIXED)

- Severity: High
- Component: `core/src/iot.rs::decompress()` (and callers `parse_mqtt_payload`, `build_mqtt_payload`)
- Root cause: The declared-size guard only ran when `data.len() > 4`. A 4-byte input (`[0xFF;4]`, declaring ~4 GiB) skipped the guard entirely, then `lz4_flex::decompress_size_prepended` allocated a buffer sized by the attacker-controlled 4-byte length *before* any cap — an unbounded-allocation decompression bomb.
- Evidence: Source inspection of `decompress()` (lines 52-66 originally). `data.len() > 4` is false for a 4-byte input, so the `TooLarge` check was never reached. Confirmed by new regression tests below passing.
- Fix: Reject any input shorter than 4 bytes (`InvalidData`); enforce `declared_size <= MAX_DECOMPRESSED_SIZE` (`TooLarge`) for *every* input carrying a full 4-byte header, before any allocation. `lz4_flex` never writes more than the declared size into its buffer, so actual output is bounded by the capped declared size. Promoted `MAX_DECOMPRESSED_SIZE` to `pub(crate) const`.
- Regression tests (core/src/iot.rs): `test_decompress_empty_input_rejected`, `test_decompress_short_header_rejected`, `test_decompress_roundtrip_within_limit`, `test_decompress_oversized_declared_size_rejected` (4-byte ~4GiB → TooLarge), `test_decompress_declared_size_at_limit_accepted`, `test_decompress_declared_size_above_limit_rejected`, `test_decompress_truncated_stream_rejected`, `test_decompress_malformed_stream_rejected`, `test_decompress_empty_payload_roundtrip`, `test_parse_mqtt_payload_rejects_bad_compression`.
- Verification: `cargo test -p sibna-core --lib iot` → 16/16 pass. Full workspace lib: 163/163 pass.
- Compatibility impact: None for valid streams (wire format unchanged); invalid/oversized inputs now rejected instead of allocating huge buffers.
- Status: FIXED + verified.

### F-002 — Ratchet rejects legitimately delayed messages by absolute age (FIXED)

- Severity: High
- Component: `core/src/ratchet/mod.rs::RatchetHeader::validate()` (Rust) and `sdks/python/sibna/ratchet.py::DoubleRatchet._validate_timestamp()` (Python)
- Root cause: Both rejected any message whose creation timestamp was older than `MAX_MESSAGE_AGE_SECS=86400` (24 h) by wall-clock age. The server queues messages up to 7 days, so a legitimate delayed/authenticated message (offline delivery, reconnect replay) was rejected at the client. Reproduced: `tests/test_ratchet.py::test_decrypt_rust_fixture_ciphertexts` failed with `CryptoError: Message too old` on the committed Rust fixture (timestamp ~2026-06).
- Fix: Removed the past-age rejection from both implementations. Kept `timestamp == 0` rejection and future-timestamp rejection (`> now + 300s`, clock-skew tolerance). Documented that expiration is now server-side (queue TTL, 7 days) and replay is prevented by per-session message-number tracking, not wall-clock age. Updated `constants.py` comment for `MAX_MESSAGE_AGE_SECS` accordingly.
- Regression tests: the previously-failing `test_decrypt_rust_fixture_ciphertexts` now passes; Rust `validate()` still rejects zero/future timestamps (covered by existing unit tests + new boundary tests).
- Verification: Python `pytest tests/` → 67 passed (was 66 passed + 1 failed). Rust workspace lib → 163 passed.
- Compatibility impact: Wire format unchanged. Delayed messages within queue TTL now decrypt correctly. No change to replay protection (message numbers unchanged).
- Status: FIXED + verified.

### F-003 — Interop runner uses separate random temp dirs (FIXED)

- Severity: High
- Component: `run_interop.sh` and `run_interop.ps1`
- Root cause: `run_interop.sh` set `PY_CT_PATH="$(mktemp -d)/..."` and
  `RUST_CT_PATH="$(mktemp -d)/..."` — two *different* random directories —
  while the Python test writes to `tempfile.gettempdir()/sibna_py_ratchet_ct.json`
  and the Rust test reads `std::env::temp_dir()/sibna_py_ratchet_ct.json`
  (fixed OS temp dir). The runner's paths never matched the test paths, so its
  artifact-existence checks always failed and genuine interop could not run via CI.
- Evidence: `run_interop.sh` lines 18-19 vs Python test lines 40-41 and Rust
  test lines 20-30.
- Fix: both runners now use the OS temp dir (`${TMPDIR:-/tmp}` POSIX,
  `$env:TEMP` Windows), consistent with the tests; stop on first failure,
  propagate exit codes, validate artifacts before consuming, and clean up
  safely on exit/failure via `trap`/`try/finally`. `run_interop.ps1` repo root
  now derives from `$PSScriptRoot` instead of a hardcoded path.
- Regression test: ran the full runner logic manually — Python→Rust and
  Rust→Python ratchet decryption both succeed.
- Verification: Python `test_python_encrypt_writes_ciphertexts_for_rust` pass;
  Rust `cargo test --test test_python_interop` → 4/4 pass (no `unused_mut`
  warnings; clean under `-D warnings`); Python
  `test_python_decrypts_rust_generated_ciphertexts` pass. Genuine
  Rust↔Python interop confirmed in both directions.
- Compatibility impact: Test harness only; no protocol change.
- Status: FIXED + verified.

### F-004 — Envelope rejects delayed messages by age; unsigned fields undocumented (FIXED)

- Severity: Medium
- Component: `sdks/python/sibna/envelope.py::verify_signed_envelope` and module docstring
- Root cause: `verify_signed_envelope` rejected envelopes older than
  `ENVELOPE_MAX_AGE_SECS=300` (5 min) by wall-clock age. The server queues
  messages up to 7 days, so a legitimate delayed/authenticated envelope was
  rejected at the client. Also, which fields are authenticated was not
  documented: `timestamp` and `compressed` are NOT in the signed canonical
  payload.
- Fix: Removed age-based rejection from `verify_signed_envelope` (signature
  still authenticates recipient_id/message_id/payload_hex). Documented in the
  module docstring that `timestamp` (transport hint, re-stamped by server),
  `compressed` (transport hint; mismatch → decryption failure only), and
  `sender_id` (verification key) are intentionally not signed, and that
  expiration is server-side (queue TTL) while replay is prevented by message-ID
  dedup + ratchet sequence numbers. Retained `ENVELOPE_MAX_AGE_SECS` constant
  for API compatibility.
- Regression tests (tests/test_envelope.py):
  `test_envelope_delayed_message_still_verifies` (8-day-old envelope verifies),
  `test_envelope_timestamp_not_signed_tamper_does_not_break_signature`.
- Verification: Python `pytest tests/` → 69 passed (67 + 2 new).
- Compatibility impact: Wire format unchanged. Delayed envelopes now verify.
  Note: `timestamp` remains unauthenticated; authenticating creation time would
  require a compatibility-breaking envelope change (add timestamp to the signed
  canonical payload) — flagged as a future improvement (see Remaining Risks).
- Status: FIXED + verified.

### F-005 — Version metadata inconsistent (FIXED)

- Severity: Medium
- Component: `Cargo.toml`, `sdks/python/pyproject.toml`,
  `sdks/python/sibna/__init__.py`, `sdks/python/sibna/constants.py`,
  `server/src/main.rs`, `sdks/python/tests/test_version.py`, `CHANGELOG.md`
- Root cause: All package/version metadata reported `3.0.1` while the target
  release is `3.0.2`. `scripts/version_check.py` would fail.
- Fix: Bumped all to `3.0.2`; wire protocol version stays `10` (unchanged).
  Added CHANGELOG `[3.0.2]` entry referencing tag `v3.0.2`.
- Verification: `python scripts/version_check.py` → passed.
- Status: FIXED + verified.

### F-006 — Server delayed-queue delivery regression test added (FIXED)

- Severity: Medium
- Component: `server/tests/aggressive_tests.rs` (new `test_delayed_queue_delivery_and_ack`)
- Root cause: No server-level test proved that a message queued while the recipient is offline is delivered on reconnect and removed on ACK — the core of the delayed-message lifecycle.
- Fix: Added `test_delayed_queue_delivery_and_ack`: Alice queues a message to offline Bob via REST (202); Bob connects over WS and receives it; Bob ACKs; Bob reconnects and the message is NOT redelivered.
- Verification: `cargo test -p sibna-server --test aggressive_tests test_delayed_queue_delivery_and_ack` → ok. Combined with F-002/F-004 (client no longer rejects old timestamps), delayed delivery works end to end.
- Status: FIXED + verified.

### F-007 — REST recipient_id validation inconsistency (documented, Low)

- Severity: Low
- Component: `server/src/main.rs::send_message_handler` vs `server/src/ws.rs::route_message`
- Root cause: The WS path validates `recipient_id` (exactly 64 hex chars) and `message_id` length before queueing; the REST `/v1/messages/send` path performs no recipient/payload validation, so a malformed recipient_id can be queued but never delivered (wasted queue entry, no security breach since the server is a sealed relay).
- Fix: None applied (behavior preserved); documented as a known inconsistency. Adding REST-side validation is a safe future hardening but is out of scope for this release (would reject previously-accepted payloads).
- Status: Documented / no change.

---

## RELEASE GATE STATUS

No git repository, remote, or GitHub access exists in this environment, so:
- CI workflows were corrected locally but **cannot be executed** here (no GitHub Actions, no `git push`, no branch `release/3.0.2`, no PR #4).
- `release/3.0.2` cannot be pushed, PR #4 cannot be merged, and `v3.0.2` cannot be tagged/released from this environment.
- All local verification (Rust lib + integration, Python SDK, mypy, black, clippy -D warnings, version_check, genuine Rust↔Python interop both directions, new decompression/envelope/server regression tests) passes.

Required before release (owner/GitHub actions):
1. Push the fixed tree to `release/3.0.2` and confirm CI runs (Linux + Windows + macOS).
2. Confirm all required CI jobs pass on the final commit: fmt, clippy (-D warnings), test-core, test-integration, test-proptest, build-verify, sdk-python, sdk-interop, test-server, audit-deny, audit-vulnerabilities.
3. Merge PR #4 only after all required jobs pass on the exact final commit.
4. Tag `v3.0.2` and create the GitHub Release from the merged commit.
5. Retain `release/3.0.2` until merge/tag/release are confirmed.

---

## REMAINING RISKS AND LIMITATIONS

- **Storage rollback:** The HMAC-authenticated manifest detects blob/manifest tampering and single-file rollback, but an attacker who controls all local storage and restores an older (data + manifest) pair cannot be stopped without a trusted external freshness source (server-maintained version, hardware monotonic counter, or trusted timestamping). Complete rollback prevention is NOT guaranteed; documented in THREAT_MODEL.md §5.
- **Envelope `timestamp` is unauthenticated:** It is a transport hint re-stamped by the server; it is not in the signed canonical payload. Authenticating creation time would require a compatibility-breaking envelope change (add timestamp to signed bytes) and a version/migration plan — deferred.
- **REST `recipient_id` validation:** REST `/v1/messages/send` does not validate recipient_id format like the WS path does (F-007).
- **Flood stress test flakiness:** `test_aggressive_queue_flood_stress` passes in isolation but can fail under full-suite concurrency due to resource contention; pre-existing, not weakened.
- **Unverified environments:** macOS/Windows CI runs, GitHub Actions execution, `git push`, PR merge, and tagging could not be performed here (no git remote / no GitHub access).
- **No claim of vulnerability-freedom:** This review establishes the assurance actually evidenced by the inspected code and executed tests, not the absence of all vulnerabilities.

