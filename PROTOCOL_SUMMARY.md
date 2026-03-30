# Sibna Protocol — Summary

**Version:** 1.0.0  
**Status:** Internally hardened — external audit pending  
**Last updated:** March 2026

---

## What is Sibna?

Sibna is a Rust implementation of the Signal Protocol — X3DH key agreement + Double Ratchet algorithm — packaged as a library you can embed in your own applications. It is not an end-user application.

The core is written in Rust with a C-compatible FFI layer, and SDKs are provided for Flutter, Python, TypeScript, C++, and Dart.

---

## Protocol design

Sibna implements two established cryptographic protocols:

### X3DH — Extended Triple Diffie-Hellman

X3DH is used to establish a shared secret between two parties asynchronously — one party can be offline when the other initiates the handshake. It uses four key types:

- **Identity key** (IK) — long-term Ed25519 signing + X25519 DH key
- **Signed prekey** (SPK) — medium-term X25519 key, signed by the identity key
- **One-time prekey** (OPK) — single-use X25519 key, consumed at handshake
- **Ephemeral key** (EK) — generated fresh for each handshake by the initiator

The shared secret is derived from four DH operations combined via HKDF-SHA256 with the domain separation constant `SibnaX3DH_SessionKeys_v9`.

### Double Ratchet

After X3DH, the Double Ratchet manages ongoing message encryption. It combines:

- **Symmetric ratchet** — derives a new message key for every message sent. Past messages cannot be decrypted even if the current state is compromised.
- **Diffie-Hellman ratchet** — after a DH round trip, the symmetric keys are re-derived from fresh DH output. This provides post-compromise security: a compromised state recovers security once both parties complete a new DH exchange.

### Group messaging

Group sessions use the Sender Key pattern: each member generates a sender key chain and distributes it to all other members via pairwise encrypted sessions. Epoch-based rotation limits the damage from member removal. The maximum skip is bounded at 500 messages to prevent memory exhaustion.

---

## Cryptographic primitives

| Primitive | Algorithm | Crate | Notes |
|---|---|---|---|
| AEAD encryption | ChaCha20-Poly1305 | `chacha20poly1305` (RustCrypto) | Preferred over AES on devices without hardware AES-NI |
| Key agreement | X25519 | `x25519-dalek` (dalek-cryptography) | |
| Digital signatures | Ed25519 | `ed25519-dalek` (dalek-cryptography) | Used for signed prekeys |
| Key derivation | HKDF-SHA256 | `hkdf` (RustCrypto) | Domain-separated with `_v9` suffix constants |
| Key derivation (alt) | HKDF-SHA512 | `hkdf` (RustCrypto) | Available via `KdfAlgorithm::HkdfSha512` |
| Message authentication | HMAC-SHA256 | `hmac` (RustCrypto) | Chain key step |
| Hash | SHA-256, SHA-512, SHA-3 | `sha2`, `sha3` (RustCrypto) | |
| Randomness | OS CSPRNG | `getrandom` | Via `OsRng`, thread-local cached |
| Zeroization | Automatic on drop | `zeroize` | All key types implement `ZeroizeOnDrop` |

---

## Security properties

| Property | Status | Mechanism |
|---|---|---|
| Forward secrecy | ✅ | Symmetric ratchet — new key per message |
| Post-compromise security | ✅ | DH ratchet — re-keying after each DH round trip |
| AEAD integrity | ✅ | ChaCha20-Poly1305 — 128-bit tag |
| Replay protection | ✅ | Per-session message counter + deduplication |
| MITM protection | ✅ (user action required) | Safety number verification |
| Memory zeroization | ✅ | `ZeroizeOnDrop` on all key types |
| Constant-time auth | ✅ | Used for AEAD tag comparison |
| DoS protection | ✅ | Rate limiter on every cryptographic entry point |
| Post-quantum | ❌ | Planned — not yet implemented |
| External audit | ❌ | Not yet conducted — see [SECURITY.md](SECURITY.md) |

---

## HKDF domain separation

All HKDF `expand()` calls use explicit info strings with the `_v9` suffix. This ensures v9 key material is cryptographically separated from v8 key material. Sessions established with v8 are **not** wire-compatible with v9 — this is intentional, as v8 contained critical vulnerabilities.

| Context | Info string |
|---|---|
| Session init (root + chain key) | `SibnaRootAndChainKey_v9` |
| Ratchet step | `SibnaRatchet_v9` |
| X3DH session keys | `SibnaX3DH_SessionKeys_v9` |
| X3DH sending key | `SibnaSendingKey_v9` |
| X3DH receiving key | `SibnaReceivingKey_v9` |
| Group message key | `SibnaGroupMessageKey_v9` |
| Group chain key | `SibnaGroupChainKey_v9` |
| Storage key | `SibnaStorageKey_v9` |

---

## Repository structure

```
sibna-protc/
├── core/src/
│   ├── crypto/         ChaCha20-Poly1305, HKDF, HMAC, random, key generation
│   ├── ratchet/        Double Ratchet — chain, session, state
│   ├── handshake/      X3DH — builder, prekey bundles, protocol
│   ├── keystore/       Identity, signed prekeys, one-time prekeys
│   ├── group/          Sender Keys, epoch-based rotation
│   ├── safety/         Safety numbers, 80-digit fingerprints
│   ├── rate_limit/     Per-operation, per-client DoS protection
│   ├── validation/     Input bounds checking
│   ├── ffi/            C-compatible FFI for all SDKs
│   └── lib.rs          SecureContext — main public API
├── sdks/
│   ├── flutter/        Flutter plugin (Android, iOS, Windows, Linux, macOS)
│   ├── dart/           Standalone Dart SDK
│   ├── python/         Python SDK
│   ├── javascript/     TypeScript SDK
│   └── cpp/            C++ headers
├── tests/
│   └── integration_tests.rs   20 integration tests
├── .github/workflows/ci.yml
├── deny.toml / clippy.toml / rustfmt.toml
└── Cargo.toml
```

---

## Platform support

| Platform | Library | Build target |
|---|---|---|
| Linux x86_64 | `libsibna.so` | `x86_64-unknown-linux-gnu` |
| macOS arm64 | `libsibna.dylib` | `aarch64-apple-darwin` |
| macOS x86_64 | `libsibna.dylib` | `x86_64-apple-darwin` |
| Windows x86_64 | `sibna.dll` | `x86_64-pc-windows-msvc` |
| Android arm64 | `libsibna.so` | `aarch64-linux-android` |
| Android armv7 | `libsibna.so` | `armv7-linux-androideabi` |
| iOS arm64 | `libsibna.a` | `aarch64-apple-ios` |

---

## Internal security hardening — v9

The following issues were found and resolved during internal code review in v9:

### Critical — 5 issues

| Issue | File | Fix |
|---|---|---|
| `mac_key` serialized into QR code payload | `safety.rs` | Key removed from serialized output entirely |
| `shared_secret` returned to API caller | `lib.rs` | Returns `peer_id` instead; secret stays internal |
| HKDF `expand()` called twice on same PRK | `session.rs` | Single 64-byte expand, then split |
| `keystore::from_bytes` panicked on bad input | `keystore/mod.rs` | Converted to `ProtocolResult<Self>` |
| `derive_key` used `?` in non-Result return | `chain.rs` | Changed return type to `CryptoResult<[u8;32]>` |

### High — 6 issues

| Issue | File | Fix |
|---|---|---|
| Group decrypt unbounded skip — DoS | `group/mod.rs` | `MAX_SKIP_GROUP = 500` added |
| `Encryptor` counter initialized to `u64::MAX` | `session.rs` | Changed to `0` |
| 4 production `.unwrap()` in `skip_message_keys` | `session.rs` | Replaced with `?` + `ProtocolError::InvalidState` |
| `add_group_member` ignored returned `Result` | `lib.rs` | Added `?` propagation |
| `SecureRandom::new().unwrap()` in builder | `builder.rs` | Proper error propagation via `HandshakeError` |
| `constant_time_cmp` documented as CT but was not | `secure_compare.rs` | Documented as non-CT, hidden from public API |

### Medium — 5 issues

| Issue | Fix |
|---|---|
| `MAX_AD_LEN = 1024` in validation vs `256` in crypto | Unified to `256` |
| FFI `sibna_last_error` always returned generic string | Thread-local `LAST_ERROR` storage |
| `burst_tokens = 100` on init — bypassed rate limiter | Changed to `0` |
| X3DH HKDF with empty salt `&[]` | Domain-separated constant `SibnaX3DH_SessionKeys_v9` |
| 30 `errors_v*.log` files in repository | Deleted |

**Result:** zero `.unwrap()` or `.expect()` outside `#[cfg(test)]` blocks.

---

## Performance

Indicative figures on Apple M2 (single-threaded, release build):

| Operation | Time |
|---|---|
| X25519 key generation | ~10 µs |
| X3DH handshake | ~80 µs |
| Message encryption (1 KB) | ~5 µs |
| Message decryption (1 KB) | ~5 µs |
| Safety number calculation | ~50 µs |

Run `cargo bench` on your target hardware for accurate measurements.

---

## Threat model summary

**Protected against:** passive eavesdropping, active MITM (with safety number verification), forward secrecy compromise, post-compromise attacks, replay attacks, timing side-channels, memory disclosure after use, DoS on cryptographic entry points.

**Not protected against:** device-level compromise, traffic metadata, safety number verification skipped by the user, and any attack class that may be discovered by an external audit that has not yet been conducted.

---

## Contact

- Security reports: [security@sibna.dev](mailto:security@sibna.dev)
- General: [info@sibna.dev](mailto:info@sibna.dev)
- GitHub: [github.com/SibnaOfficial/sibna-protc](https://github.com/SibnaOfficial/sibna-protc)
