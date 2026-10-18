# Sibna Protocol v3.0.2

A high-security implementation of the X3DH handshake, the Double Ratchet, and
sender-key group messaging — with a relay server, a native Rust core, and the
**Python SDK as the sole official language binding**.

> [!CAUTION]
> **Security disclaimer**: this protocol is an experimental research prototype.
> It has **not** undergone an independent third-party cryptographic review or
> formal security audit. Use it for research and evaluation only.

---

## Repository layout

```
.
├── core/                 # Rust protocol core (X3DH, Double Ratchet, groups,
│   ├── src/              #   padding, storage, keystore, P2P transport)
│   ├── tests/            #   cargo unit + integration tests
│   ├── fuzz/             #   cargo-fuzz harnesses
│   ├── kani/             #   Kani model-checking harnesses
│   └── Cargo.toml
├── server/               # Axum-based relay server (REST + WebSocket)
├── sdks/
│   └── python/           # sole official SDK (pure Python cryptography +
│       │                 #   relay client, no FFI/native dependency)
│       ├── sibna/        #   package
│       ├── tests/        #   pytest conformance suite
│       ├── pyproject.toml
│       └── README.md
├── tests/                # shared interop + security tests (cross-SDK padding
│   └── cross_sdk/        #   vectors, etc.)
├── scripts/              # version consistency check (scripts/version_check.py)
├── .github/workflows/    # CI: fmt, clippy, tests, audits, Python conformance
├── PROTOCOL_SPECIFICATION.md   # normative wire-format specification
├── SECURITY.md           # security policy & disclosure
├── THREAT_MODEL.md       # attacker model & residual risks
├── CHANGELOG.md          # release history
├── CONTRIBUTING.md       # contribution rules
└── LICENSE               # Apache-2.0 OR MIT (dual)
```

---

## What Sibna Protocol is

Sibna Protocol is an end-to-end encrypted communication protocol stack. Its
goal is confidential, forward-secret, post-compromise-secure messaging between
two or more parties, with optional post-quantum protection at handshake time.

The protocol is specified in [`PROTOCOL_SPECIFICATION.md`](PROTOCOL_SPECIFICATION.md).
This repository contains three maintained components plus shared
tests:

| Component | Role |
|-----------|------|
| **Protocol specification** | The normative contract: wire formats, X3DH transcript, Double Ratchet, padding, envelope signing, storage manifest, versioning. |
| **Rust core** (`core/`) | Native implementation of the protocol (X3DH with hybrid ML-KEM-768, Double Ratchet, sender-key groups, storage, keystore, P2P transport). |
| **Relay server** (`server/`) | Axum-based HTTP/WebSocket relay: Ed25519 challenge-response auth, HS256 JWT, prekey management, sealed-envelope routing, offline queue. |
| **Python SDK** (`sdks/python/`) | **Sole official SDK.** Pure-Python implementation of the full protocol stack (no FFI, no native library, no Rust core required). |
| **Shared tests** (`tests/`) | Cross-component interop fixtures (padding vectors) and security tests. |

### Cryptographic components

| Layer | Algorithm |
|-------|-----------|
| Identity / signing | Ed25519 |
| Key agreement | X25519 Diffie-Hellman |
| Handshake | X3DH (Ed25519 identity + X25519 DH + signed/one-time prekeys) |
| Post-quantum | ML-KEM-768 (FIPS 203) hybrid at X3DH (default ON) |
| Session encryption | Double Ratchet (HMAC-SHA256 symmetric ratchet + X25519 DH ratchet) |
| AEAD | ChaCha20-Poly1305 (RFC 8439), 12-byte nonce, 16-byte tag |
| KDF | HKDF-SHA256 |
| Transcript hash | BLAKE3 (mandatory) |
| Group messaging | Sender keys with per-sender chains, Ed25519-signed distribution |
| Identity verification | Safety numbers (SHA-512 fingerprint, 80 decimal digits) |
| Padding | Block-aligned with random prefix (1-8 B) and randomized suffix (0-7 blocks) |
| Envelope | Length-prefix canonical form, Ed25519 signature |
| Storage | ChaCha20-Poly1305-encrypted, HMAC-authenticated manifest (rollback protection) |
| Relay transport | HTTP + WebSocket, JWT auth |

The Rust core is the reference implementation. The Python SDK is implemented
independently (pure Python, maintained libraries only) and is kept synchronized
with the Rust core through automated conformance tests in CI.

### Security status

Sibna is an **experimental research prototype**. It has **not** undergone an
independent third-party cryptographic review or formal security audit. See
[`SECURITY.md`](SECURITY.md), [`THREAT_MODEL.md`](THREAT_MODEL.md), and the
"Security assumptions" section below for details.

---

## The single official SDK: Python

`sdks/python/` is the only maintained SDK. It is a self-contained, pure-Python
implementation of the Sibna Protocol: X3DH, Double Ratchet, sender-key groups,
safety numbers, signed envelopes, encrypted storage, and the relay HTTP/WebSocket
client. It requires no Rust core, FFI, or native library.

Install and quick start are documented in [`sdks/python/README.md`](sdks/python/README.md).

---

## Quick start (Python SDK)

```bash
cd sdks/python
pip install -e .           # or: pip install sibna  (when published)
```

```python
from sibna import Session, PreKeyBundle
from sibna.crypto import X25519KeyPair, Ed25519KeyPair, derive_identity_keys
import hashlib

# --- Alice (initiator) ---
alice_ed, alice_x = derive_identity_keys(hashlib.sha256(b"alice").digest())
bob_ed, bob_x = derive_identity_keys(hashlib.sha256(b"bob").digest())
bob_spk = X25519KeyPair.generate()
bundle = PreKeyBundle(
    identity_key=bob_ed.public_key,
    x25519_identity_key=bob_x.public_key,
    signed_prekey=bob_spk.public_key,
    signed_prekey_signature=bob_ed.sign(b"SibnaSignedPreKey_v3" + bob_spk.public_key),
)

alice = Session()
eph = X25519KeyPair.generate()
alice.initiate_as_initiator(alice_x, eph, bundle)
ct = alice.encrypt(b"Hello Bob")

# --- Bob (responder) ---
bob = Session()
bob.initiate_as_responder(bob_x, bob_spk, None, alice_x.public_key, eph.public_key)
assert bob.decrypt(ct) == b"Hello Bob"
```

The SDK public API is documented in [`sdks/python/README.md`](sdks/python/README.md)
and in the module docstrings.

---

## Protocol compatibility and versioning

| Item | Value |
|------|-------|
| Protocol specification | v3.0.2 |
| Wire-format version | 10 |
| Minimum compatible wire version | 9 |
| Rust workspace / core package | 3.0.2 |
| Python SDK package | 3.0.2 |

The package version, Rust workspace version, and protocol wire version are kept
in sync automatically by [`scripts/version_check.py`](scripts/version_check.py),
which runs as a mandatory CI gate. A protocol-affecting change (spec, Rust core,
or Python behavior) must update the version, the conformance tests, and this
documentation together, and must pass the Python conformance gate.

See `PROTOCOL_SPECIFICATION.md` section 8 for the wire-format version constants
and `CHANGELOG.md` for the release history and versioning policy.

---

## Running tests

### Rust core

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
```

### Python SDK

```bash
cd sdks/python
pip install -e ".[dev]"
python -m pytest tests/ -v          # unit + protocol-conformance tests
python -m black --check sibna tests
python -m mypy sibna
python scripts/version_check.py   # from repo root
```

### Full validation

The CI gate (`.github/workflows/ci.yml`) runs, on every push and pull request:
Rust fmt/clippy/test, the Python lint/type/conformance suite, the version
consistency check, and the package build + clean-install smoke test. Weekly
jobs additionally run fuzzing, Kani model checking, MIRI, offensive tests, and
audit tests.

---

## Security assumptions and known limitations

- **No external audit.** The protocol and its implementations have not been
  independently reviewed. Do not deploy in high-risk environments without an
  audit.
- **Software-only key storage.** Forward secrecy holds at the protocol layer;
  on-disk key material is protected by Argon2id + ChaCha20-Poly1305 (Rust core)
  or Argon2id-equivalent HKDF key derivation (Python), but an attacker with
  persistent filesystem access can recover past material.
- **MITM protection** requires out-of-band Safety Number verification
  (Trust-On-First-Use applies until verified).
- **No anonymity.** IP addresses, packet sizes, timing, and participant
  identities are visible to the relay and network observers. Optional SOCKS5/Tor
  proxying is available in the Rust core P2P feature only; it is not bundled
  and does not protect against endpoint traffic analysis.
- **Post-quantum protection** requires the `pqc` feature (enabled by default in
  the Rust core) and the `pqcrypto` dependency in the Python SDK. X25519 alone
  is broken by a sufficiently powerful quantum computer.

See [`SECURITY.md`](SECURITY.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) for
the full adversarial model, mitigations, and residual risks.

---

## Vulnerability reporting and contribution

**Do not open public issues for security vulnerabilities.** Report them
privately to `contact.sibna.dev` (see [`SECURITY.md`](SECURITY.md)).

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
submission process: fork, feature branch, run the checks in this README, open a
pull request.

Protocol-affecting changes must update the specification, the Rust core, the
Python SDK, the conformance tests, and the version metadata together, and must
pass the mandatory Python conformance CI gate.

## License

Apache License 2.0 / MIT (dual). See [`LICENSE`](LICENSE).
