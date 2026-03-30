# Sibna Protocol

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-534AB7.svg" alt="v1.0.0">
  <img src="https://img.shields.io/badge/security-hardened-1D9E75.svg" alt="Security Hardened">
  <img src="https://img.shields.io/badge/audit-pending-BA7517.svg" alt="External Audit Pending">
  <img src="https://img.shields.io/badge/license-Apache%202.0%20%7C%20MIT-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust 1.75+">
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android%20%7C%20iOS-blue.svg" alt="Platforms">
</p>

<p align="center">
  A production-hardened Signal Protocol implementation in Rust.<br>
  Same cryptographic guarantees as Signal — under your full control.
</p>

---

> Warning: **Security notice:** Sibna Protocol has undergone extensive internal security hardening (v1.0 baseline). An **independent external audit has not yet been performed**. Do not use this library in production systems handling sensitive data until an external audit is complete. See [Security](#security) for details.

---

## What is Sibna?

Sibna is a **protocol library**, not an application. It implements the [Signal Protocol](https://signal.org/docs/) — X3DH key agreement + Double Ratchet — in Rust, and exposes it through SDKs for Flutter, Python, TypeScript, C++, and Dart.

**Use Sibna when you want to build your own E2E-encrypted application** without depending on Signal's infrastructure or its license.

```
Signal (the app)  →  ready-made, runs on Signal's servers, GPLv3
Sibna Protocol    →  build your own app, your own servers, Apache-2.0 / MIT
```

---

## Features

- **X3DH key agreement** — Extended Triple Diffie-Hellman with domain-separated HKDF
- **Double Ratchet** — forward secrecy and post-compromise security per session
- **ChaCha20-Poly1305** — AEAD encryption, faster than AES on devices without hardware AES-NI
- **Group messaging** — Sender Keys with epoch-based rotation and bounded skip
- **Safety numbers** — 80-digit human-verifiable identity fingerprints
- **Rate limiting** — DoS protection on every cryptographic entry point
- **Memory zeroization** — all key material zeroed on drop via `ZeroizeOnDrop`
- **Zero production panics** — every error path returns `Result`, no `.unwrap()` in production code
- **Multi-platform** — Windows, Linux, macOS, Android, iOS

---

## Platform support

| Platform | Status | Output |
|---|---|---|
| Linux x86_64 | ✅ | `libsibna.so` |
| macOS (arm64, x86_64) | ✅ | `libsibna.dylib` |
| Windows x86_64 (MSVC) | ✅ | `sibna.dll` |
| Android (arm64, armv7, x86_64) | ✅ | `libsibna.so` |
| iOS arm64 | ✅ | `libsibna.a` (static) |
| WASM | Planned | planned |

## SDK support

| Language | Path | Status |
|---|---|---|
| Rust | `core/` | ✅ Complete |
| Flutter / Dart | `sdks/flutter/` | ✅ Complete (session E2E pending FFI exposure) |
| Python | `sdks/python/` | ✅ Crypto layer complete |
| TypeScript | `sdks/javascript/` | ✅ Crypto layer complete |
| C++ | `sdks/cpp/` | ✅ Headers complete |
| Dart (standalone) | `sdks/dart/` | ✅ Complete |

---

## Quick start

### Rust

```toml
# Cargo.toml
[dependencies]
sibna-core = { path = "./core" }
```

```rust
use sibna_core::{SecureContext, Config};
use sibna_core::crypto::{CryptoHandler, KeyGenerator};

// Create a context — password needs uppercase + lowercase + digit, ≥8 chars
let ctx = SecureContext::new(Config::default(), Some(b"MyStr0ngPass!"))?;

// Generate an identity key pair
let identity = ctx.generate_identity()?;

// Standalone encryption (no session required)
let key     = KeyGenerator::generate_key()?;
let handler = CryptoHandler::new(key.as_ref())?;

let ciphertext = handler.encrypt(b"Hello, World!", b"associated-data")?;
let plaintext  = handler.decrypt(&ciphertext, b"associated-data")?;
```

### Flutter

```yaml
# pubspec.yaml
dependencies:
  sibna_flutter:
    path: ./sdks/flutter
```

```dart
import 'package:sibna_flutter/sibna_flutter.dart';

// Initialize once, before runApp()
await SibnaFlutter.initialize();

// Standalone crypto
final key = SibnaCrypto.generateKey();
final ct  = SibnaCrypto.encrypt(key, plaintext, associatedData: aad);
final pt  = SibnaCrypto.decrypt(key, ct, associatedData: aad);

// Identity verification — show to user for out-of-band comparison
final sn = SibnaSafetyNumber.calculate(myPublicKey, theirPublicKey);
print(sn.formatted); // "12345 67890 12345 ..."
```

### Python

```python
import sibna

key        = sibna.Crypto.generate_key()
ciphertext = sibna.Crypto.encrypt(key, b"Hello, World!")
plaintext  = sibna.Crypto.decrypt(key, ciphertext)
```

### TypeScript

```typescript
import { Crypto, init } from 'sibna-protocol';

await init();

const key       = Crypto.generateKey();
const encrypted = Crypto.encrypt(key, new TextEncoder().encode("Hello, World!"));
const decrypted = Crypto.decrypt(key, encrypted);
```

---

## Building the native library

```bash
# Linux / macOS
cargo build --release --package sibna-core --features ffi

# Windows (MSVC) — do NOT add crt-static on Windows MSVC
cargo build --release --package sibna-core --features ffi \
  --target x86_64-pc-windows-msvc

# Android (requires NDK r26+)
cargo build --release --features ffi --target aarch64-linux-android
cargo build --release --features ffi --target armv7-linux-androideabi
cargo build --release --features ffi --target x86_64-linux-android

# iOS
cargo build --release --features ffi --target aarch64-apple-ios
```

| Platform | Output path |
|---|---|
| Linux | `target/release/libsibna.so` |
| macOS | `target/release/libsibna.dylib` |
| Windows | `target/release/sibna.dll` |
| Android | `target/<ABI>/release/libsibna.so` |
| iOS | `target/aarch64-apple-ios/release/libsibna.a` |

---

## Repository structure

```
sibna-protc/
├── core/src/
│   ├── crypto/         ChaCha20-Poly1305, HKDF, HMAC, random, key generation
│   ├── ratchet/        Double Ratchet — chain, session, state management
│   ├── handshake/      X3DH — builder, protocol, prekey bundles
│   ├── keystore/       Identity, signed prekeys, one-time prekeys
│   ├── group/          Sender Keys, epoch-based rotation
│   ├── safety/         Safety numbers, QR code verification
│   ├── rate_limit/     Per-operation, per-client DoS protection
│   ├── validation/     Input bounds and type checking
│   ├── ffi/            C-compatible FFI for all language SDKs
│   └── lib.rs          SecureContext — main public API
├── sdks/
│   ├── flutter/        Flutter plugin (Android, iOS, Windows, Linux, macOS)
│   ├── dart/           Standalone Dart SDK
│   ├── python/         Python SDK
│   ├── javascript/     TypeScript SDK
│   └── cpp/            C++ headers and source
├── tests/
│   └── integration_tests.rs   20 end-to-end integration tests
├── .github/workflows/ci.yml   CI: audit, deny, clippy, miri, cross-platform
├── deny.toml                  Dependency policy — licenses, advisories, bans
├── clippy.toml                Strict clippy configuration
└── rustfmt.toml               Unified code formatting
```

---

## Cryptographic primitives

| Primitive | Algorithm | Crate |
|---|---|---|
| AEAD encryption | ChaCha20-Poly1305 | `chacha20poly1305` (RustCrypto) |
| Key agreement | X25519 | `x25519-dalek` (dalek-cryptography) |
| Digital signatures | Ed25519 | `ed25519-dalek` (dalek-cryptography) |
| Key derivation | HKDF-SHA256 / HKDF-SHA512 | `hkdf` (RustCrypto) |
| Message authentication | HMAC-SHA256 | `hmac` (RustCrypto) |
| Hash | SHA-256, SHA-512, SHA-3 | `sha2`, `sha3` (RustCrypto) |
| Randomness | OS CSPRNG | `getrandom` |
| Zeroization | Automatic on drop | `zeroize` |

All cryptographic crates are from [RustCrypto](https://github.com/RustCrypto) or [dalek-cryptography](https://github.com/dalek-cryptography). These upstream libraries have received independent security reviews.

---

## Production Hardening — v1.0.0

The v1.0.0 release represents a significant hardening milestone, resolving numerous theoretical and practical issues identified during internal code review. **This is not a substitute for an independent external audit.**

| Severity | Count | Examples |
|---|---|---|
| Critical | 5 | `mac_key` leaked in QR payload · `shared_secret` returned to API caller · HKDF `expand()` called twice on same PRK |
| High | 6 | Group decrypt DoS via unbounded skip · `Encryptor` counter init at `u64::MAX` · 4 production panics in `skip_message_keys` |
| Medium | 5 | `MAX_AD_LEN` mismatch between validation and crypto layers · FFI always-generic error string · `burst_tokens=100` bypassed rate limiter on init |

**Result:** zero `.unwrap()` / `.expect()` outside `#[cfg(test)]` blocks.

Full details in [CHANGELOG.md](CHANGELOG.md).

---

## Security

Sibna Protocol has been internally reviewed and hardened. It has **not undergone an independent external security audit by a specialized cryptography firm**.

This is a meaningful distinction. For any deployment handling sensitive data — medical records, financial information, communications that could endanger people — an external audit is required before deployment.

**To report a vulnerability:**

Email [security@sibna.dev](mailto:security@sibna.dev). Do not open public GitHub issues for security reports.

Please include: a description of the issue, steps to reproduce, potential impact, and a suggested fix if you have one.

See [SECURITY.md](SECURITY.md) for the full responsible disclosure policy.

---

## Threat model

**Protected against:**
- Passive eavesdropping — ChaCha20-Poly1305 with unique nonces per message
- Active MITM — safety number verification
- Forward secrecy compromise — Double Ratchet key rotation
- Post-compromise recovery — ratchet re-keying on new DH round
- Replay attacks — per-session message counter and deduplication
- Timing side-channels — constant-time comparisons throughout
- Memory disclosure — `ZeroizeOnDrop` on all key material
- DoS on crypto operations — rate limiter on every entry point

**Outside the threat model:**
- Device-level compromise (OS or hardware attacker)
- Safety number verification skipped by the user
- Traffic metadata — who communicates, when, and how often
- No external audit has been conducted — this is a known and acknowledged gap

---

## Running the tests

```bash
# All tests
cargo test --all

# Strict linting (matches CI)
cargo clippy --all-targets -- \
  -D warnings \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic

# Dependency vulnerability audit
cargo audit

# Dependency policy (licenses, advisories, banned crates)
cargo deny check

# Undefined behaviour check — Linux only, nightly required
cargo +nightly miri test --package sibna-core \
  crypto::secure_compare crypto::random -- --test-threads=1
```

---

## Performance

Indicative benchmarks on Apple M2 (single-threaded, release build):

| Operation | Approximate time |
|---|---|
| X25519 key generation | ~10 µs |
| X3DH handshake | ~80 µs |
| Message encryption (1 KB) | ~5 µs |
| Message decryption (1 KB) | ~5 µs |
| Safety number calculation | ~50 µs |

Run `cargo bench` on your target hardware for accurate figures.

---

## Configuration

```rust
use sibna_core::Config;

let config = Config {
    max_skipped_messages:   500,                // bounded — prevents memory exhaustion
    key_rotation_interval:  86_400,             // seconds (24 h)
    handshake_timeout:      30,
    enable_group_messaging: true,
    max_group_size:         256,
    enable_rate_limiting:   true,
    max_message_size:       10 * 1024 * 1024,   // 10 MB
    session_timeout_secs:   3_600,              // 1 h
    auto_prune_keys:        true,
    max_key_age_secs:       30 * 86_400,        // 30 days
    ..Default::default()
};
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

- No `.unwrap()` or `.expect()` outside `#[cfg(test)]`
- No custom cryptographic primitives — use existing audited crates only
- All public API must include documentation with security notes
- Run `cargo clippy`, `cargo audit`, and `cargo fmt` before submitting a PR

---

## License

Dual-licensed under your choice of:

- [Apache License 2.0](LICENSE)
- MIT License

Commercial use is permitted under both licenses.

---

## Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) — cryptographic primitives
- [dalek-cryptography](https://github.com/dalek-cryptography) — Curve25519 and Ed25519
- [Signal Protocol specification](https://signal.org/docs/) — the cryptographic design this library implements

---

<p align="center">
  Rust · Apache-2.0 / MIT · External audit pending
</p>
