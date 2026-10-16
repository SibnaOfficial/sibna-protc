# Sibna Protocol — Python SDK (sole official SDK)

Pure-Python implementation of the Sibna Protocol v3.0.1: X3DH handshake, hybrid
ML-KEM-768 post-quantum key agreement, Double Ratchet session encryption,
sender-key group messaging, safety numbers, signed envelopes, encrypted storage,
and the relay HTTP/WebSocket client.

**No Rust core, FFI, or native library is required.** All cryptography is
provided by maintained libraries (`cryptography`, `blake3`, `pqcrypto`). The SDK
is kept in sync with the retained Rust core (`core/`) and the normative
specification (`PROTOCOL_SPECIFICATION.md`) through automated conformance tests
that run in CI.

> [!CAUTION]
> Sibna is an experimental research prototype. It has **not** undergone an
> independent third-party cryptographic review or formal security audit.
> See [`SECURITY.md`](https://github.com/SibnaOfficial/sibna-protc/blob/main/SECURITY.md)
> and [`THREAT_MODEL.md`](https://github.com/SibnaOfficial/sibna-protc/blob/main/THREAT_MODEL.md).

---

## What this SDK implements

| Capability | Module |
|------------|--------|
| Ed25519 / X25519 keypairs, low-order point rejection | `sibna.crypto` |
| HKDF-SHA256, HMAC-SHA256, SHA-256, SHA-512 | `sibna.crypto` |
| BLAKE3 transcript hash (mandatory) | `sibna.crypto` |
| ChaCha20-Poly1305 AEAD | `sibna.crypto` |
| ML-KEM-768 hybrid KEM (FIPS 203) | `sibna.crypto` |
| X3DH initiator + responder, SPK signature verification | `sibna.x3dh` |
| Double Ratchet sessions (Rust wire-compatible) | `sibna.ratchet`, `sibna.session` |
| Sender-key groups, key distribution, signed group messages | `sibna.group` |
| Safety numbers (80 digits) | `sibna.safety_number` |
| Length-prefix signed envelopes | `sibna.envelope` |
| Block-aligned metadata-resistant padding | `sibna.padding` |
| Encrypted storage with rollback protection | `sibna.storage` |
| Relay HTTP + WebSocket client (JWT auth) | `sibna.client` |

The SDK is **not** merely an envelope/transport layer: it implements the full
cryptographic stack (X3DH, Double Ratchet, groups) and can be used standalone
without the Rust core or any relay server.

---

## Requirements

- Python 3.9+
- Mandatory: `cryptography`, `blake3`, `pqcrypto`, `requests`, `aiohttp`
- Optional (dev): `pytest`, `pytest-cov`, `pytest-asyncio`, `mypy`, `black`

## Installation

```bash
# from this directory
pip install -e ".[dev]"

# or, once published:
pip install sibna
```

`pyproject.toml` declares `cryptography`, `blake3`, `pqcrypto`, `requests`, and
`aiohttp` as mandatory dependencies. `requests`/`aiohttp` are required by the
relay client (`sibna.client`); the cryptographic modules work with just
`cryptography`, `blake3`, and `pqcrypto`.

## Quick start — end-to-end encrypted session

```python
from sibna import Session, PreKeyBundle
from sibna.crypto import (
    X25519KeyPair,
    Ed25519KeyPair,
    derive_identity_keys,
)

# --- Bob publishes a prekey bundle ---
bob_ed, bob_x = derive_identity_keys(b"bob-master-seed-32bytes!!")
bob_spk = X25519KeyPair.generate()
bundle = PreKeyBundle(
    identity_key=bob_ed.public_key,
    x25519_identity_key=bob_x.public_key,
    signed_prekey=bob_spk.public_key,
    signed_prekey_signature=bob_ed.sign(
        b"SibnaSignedPreKey_v3" + bob_spk.public_key
    ),
)

# --- Alice initiates ---
alice_ed, alice_x = derive_identity_keys(b"alice-master-seed-32bytes!!")
alice = Session()
eph = X25519KeyPair.generate()
alice.initiate_as_initiator(alice_x, eph, bundle)
ct = alice.encrypt(b"Hello Bob")

# --- Bob responds ---
bob = Session()
bob.initiate_as_responder(bob_x, bob_spk, None, alice_x.public_key, eph.public_key)
assert bob.decrypt(ct) == b"Hello Bob"

ct2 = bob.encrypt(b"Hi Alice")
assert alice.decrypt(ct2) == b"Hi Alice"
```

## Module layout

```
sdks/python/
├── pyproject.toml        # packaging (setuptools)
├── README.md             # this document
├── sibna/
│   ├── __init__.py       # public API + version
│   ├── py.typed          # PEP 561 marker
│   ├── constants.py      # protocol versions, wire formats, KDF strings
│   ├── errors.py         # typed exceptions
│   ├── crypto.py         # primitives (Ed25519, X25519, HKDF, HMAC, SHA,
│   │                     #   BLAKE3, ChaCha20-Poly1305, ML-KEM-768)
│   ├── padding.py        # block-aligned metadata-resistant padding
│   ├── x3dh.py           # X3DH handshake (initiator/responder, SPK validation)
│   ├── ratchet.py        # Double Ratchet (Rust wire-compatible)
│   ├── session.py        # Session (X3DH + Double Ratchet)
│   ├── group.py          # sender-key groups
│   ├── safety_number.py  # 80-digit fingerprints
│   ├── envelope.py       # signed envelopes (canonical length-prefixed form)
│   ├── storage.py        # encrypted storage + rollback protection
│   └── client.py         # relay HTTP + WebSocket client
└── tests/                # pytest conformance suite
```

## Public API overview

### `sibna.crypto` — primitives

`X25519KeyPair`, `Ed25519KeyPair`, `derive_identity_keys(seed)`,
`blake3_hash`, `sha256`, `sha512`, `hkdf`, `hkdf_extract`, `hkdf_expand`,
`hmac_sha256`, `random_bytes`, `chacha20_poly1305_encrypt/decrypt`,
`ml_kem_768_keypair/encapsulate/decapsulate`, `LOW_ORDER_POINTS`.

### `sibna.x3dh` — handshake

`PreKeyBundle`, `X3DHResult`, `x3dh_initiator`, `x3dh_responder`,
`generate_peer_bundle`. The SPK signature is verified over
`b"SibnaSignedPreKey_v3" ‖ SPK` before any DH computation (spec §2.2).

### `sibna.ratchet` / `sibna.session` — sessions

`DoubleRatchet`, `ChainKey`, `Session`, `SessionConfig`. Wire format matches
the Rust core: `header(56) ‖ encryptor_frame`, where the frame is
`msg_number(8) ‖ timestamp(8) ‖ padding(8) ‖ nonce(12) ‖ ct ‖ tag`, and the
AEAD associated data is `caller_AD ‖ header ‖ frame_header`.

### `sibna.group` — sender-key groups

`SenderKey`, `SenderKeyMessage`, `GroupMessage`, `GroupSession`. Key
distribution messages are Ed25519-signed and bind `group_id ‖ key_id ‖
encrypted_key ‖ timestamp`.

### `sibna.safety_number` — verification

`SafetyNumber.calculate(our, their)` — 80 digits, SHA-512 fingerprint, keys
sorted lexicographically. `SafetyNumber.parse`, `verify`, `qr_data`.

### `sibna.envelope` — signed relay envelopes

`make_signed_envelope`, `verify_signed_envelope`. Canonical payload:
`u64_be(len)‖recipient_id ‖ u64_be(len)‖message_id ‖ u64_be(len)‖payload_hex`,
signed over `SHA-512(canonical)`.

### `sibna.padding` — padding

`pad_message` / `unpad_message` (aliases `pad_payload`/`unpad_payload`).
Format: `prefix_len(1) ‖ prefix_noise(1–8) ‖ plaintext ‖ padding ‖
pad_len(2 LE)`, aligned to 1024-byte blocks with 0–7 randomized extra blocks
(SIBNA-2026-018).

### `sibna.storage` — encrypted storage

`SecureStorage` — ChaCha20-Poly1305-encrypted payload with an HMAC-authenticated
manifest and rollback (sequence-number) protection.

### `sibna.client` — relay client

`Identity`, `SibnaClient` (sync HTTP), `AsyncSibnaClient` (WebSocket).
Authentication is Ed25519 challenge-response → HS256 JWT; the JWT is sent via
the WebSocket `?token=` query parameter matching the relay server. TLS
certificate pinning is supported via `pinned_cert` and is never silently
disabled.

---

## Version compatibility

| Item | Value |
|------|-------|
| Protocol specification | v3.0.1 |
| Wire-format version | 10 |
| Minimum compatible wire version | 9 |
| Python SDK package | 3.0.1 |

The Python package version, Rust workspace version, and protocol wire version
are validated together by [`scripts/version_check.py`](../../scripts/version_check.py),
which runs as a mandatory CI gate.

---

## Running tests

```bash
cd sdks/python
pip install -e ".[dev]"
python -m pytest tests/ -v
python -m black --check sibna tests
python -m mypy sibna
```

The full suite (unit + protocol-conformance, including cross-implementation
vectors against the Rust core) runs on every push and pull request in CI.

---

## Security notes

- **BLAKE3 is mandatory** for X3DH transcript hashing. It is imported at
  module load time; if unavailable, the SDK fails loudly rather than silently
  substituting SHA-256.
- **Signed prekeys are verified** (`b"SibnaSignedPreKey_v3" ‖ SPK`) before any
  DH computation; invalid bundles are rejected.
- **ML-KEM-768** is integrated into the X3DH handshake (default ON) and tested
  for initiator/responder agreement.
- **TLS certificate verification is never disabled.** Use `pinned_cert` for
  pinning; without it the client validates against the system trust store and
  warns.
- **No secrets are logged.** Diagnostic representations redact private key
  material.
- **No silent fallbacks.** If a protocol-required primitive (e.g. BLAKE3,
  ML-KEM-768) is unavailable, the operation fails clearly.

This SDK is **not** production-audited. It is an experimental research
prototype. See [`SECURITY.md`](https://github.com/SibnaOfficial/sibna-protc/blob/main/SECURITY.md)
and [`THREAT_MODEL.md`](https://github.com/SibnaOfficial/sibna-protc/blob/main/THREAT_MODEL.md).

---

## What is *not* supported

The following are implemented in the Rust core but are **not** ported to this
Python SDK, and are explicitly *not* advertised as supported here:

- OS-level P2P facilities: mDNS discovery, STUN, IGD port mapping (the Rust
  `p2p` feature). These depend on non-Python-native crates (`mdns-sd`, `if-addrs`,
  `igd`, `stun`) and are not part of the Python SDK's supported contract.
- The Rust core's FFI/WASM bindings (`ffi`, `wasm` features). The Python SDK
  is pure Python and does not load `libsibna`.

If you need P2P transport or FFI, use the Rust core directly.

---

## License

Apache License 2.0 / MIT (dual). See [`LICENSE`](https://github.com/SibnaOfficial/sibna-protc/blob/main/LICENSE).
