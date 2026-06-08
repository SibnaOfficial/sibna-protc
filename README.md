# Sibna Protocol v3.0.1

A high-security implementation of the X3DH handshake, the Double Ratchet, and sender-key group messaging — with a relay server, a native core, and language bindings for seven platforms.

> [!CAUTION]
> **Security disclaimer**: this protocol is an experimental research prototype. It has **not** undergone an independent third-party cryptographic review or formal security audit. Use it for research and evaluation only.

---

## Repository layout

```
.
├── core/                 # Rust core: X3DH, Double Ratchet, groups, padding, storage
│   ├── src/
│   ├── tests/            # cargo tests (including proptest property tests)
│   ├── fuzz/             # cargo-fuzz harnesses (8 targets)
│   ├── kani/             # Kani model-checking harnesses
│   └── tests/            # integration tests
├── server/               # Axum-based relay server (REST + WebSocket)
├── sdks/                 # language bindings
│   ├── python/           # pure-Python relay client (envelope + transport)
│   ├── javascript/       # TypeScript / Node.js relay client
│   ├── go/               # Go relay client
│   ├── java/             # Java 17+ full cryptography stack (X3DH + Double Ratchet + groups)
│   ├── dart/             # Dart FFI bindings to the native core
│   ├── flutter/          # Flutter plugin (FFI bindings + value types)
│   └── cpp/              # pure C++17 + OpenSSL 3 implementation
├── docs/                 # threat model
└── .github/workflows/    # CI: format, clippy, tests, fuzz, Kani, MIRI, audit, deny, outdated
```

---

## Protocol Overview

Sibna implements a complete end-to-end encryption protocol stack:

| Layer | Specification |
|-------|---------------|
| **Key Agreement** | X3DH with Ed25519 identity + X25519 key agreement, signed prekeys, optional one-time prekeys |
| **Session Encryption** | Double Ratchet (Signal-style) with HMAC-SHA256 symmetric ratchet and X25519 DH ratchet |
| **Group Messaging** | Sender-key protocol with per-sender key chains, key distribution via X25519 + ChaCha20-Poly1305 |
| **AEAD** | ChaCha20-Poly1305 (RFC 8439) with 12-byte nonce, 16-byte tag |
| **KDF** | HKDF-SHA256 for all key derivations |
| **Transcript Hash** | SHA-256 (portable Blake3 substitute) |
| **Padding** | Block-aligned (1KB) with random prefix (1-8 bytes) and suffix (0-7 extra blocks) |
| **Relay Transport** | REST + WebSocket with JWT auth, optional SOCKS5/Tor proxy |

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Sibna Core (Rust)                        │
│  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌───────────────┐  │
│  │  X3DH    │ │ Double Ratchet│ │ Groups   │ │ Padding/Store │  │
│  └──────────┘ └──────────────┘ └──────────┘ └───────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────────┐  ┌────────────┐
        │ C++17    │   │ Java 17+     │  │ Go         │  (full crypto)
        └──────────┘   └──────────────┘  └────────────┘
              │               │               │
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────────┐  ┌────────────┐
        │ Dart/    │   │ Python       │  │ JavaScript │  (FFI / relay clients)
        │ Flutter  │   └──────────────┘  └────────────┘
        └──────────┘
```

The Rust core implements all cryptographic primitives. C++, Java, and Go have independent reimplementations. Dart/Flutter, Python, and JavaScript are FFI bindings or relay clients.

---

## SDK Capability Matrix

| Capability | Rust | Python | JavaScript | Go | Java | Dart (FFI) | Flutter (FFI) | C++ |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Ed25519 identity | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| X25519 / ECDH | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| X3DH handshake | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ (validate) |
| Double Ratchet | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ (session) |
| Session encrypt/decrypt | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ |
| Sender-key group | ✅ | ❌ | ❌ | ❌ | ✅ | stub | create only | ✅ |
| Safety number | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Verification QR | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| ChaCha20-Poly1305 | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| SHA-256 / SHA-512 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | SHA-256 |
| HMAC-SHA-256 | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| HKDF | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Block padding | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Relay HTTP | n/a | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Relay WebSocket | n/a | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| TLS pinning | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | n/a | n/a |

> **Read per-SDK README** (`sdks/<lang>/README.md`) for exact API surface. ✅ means capability exists somewhere in the SDK; public API may be narrower.

### Rust core

```toml
[dependencies]
sibna-core = { version = "3.0.1", features = ["pqc", "p2p"] }
```

```rust
use sibna_core::{SecureContext, Config};

let ctx = SecureContext::new(Config::default(), Some(b"MasterPassword"))?;
let identity = ctx.generate_identity()?;
let mut router = HybridRouter::new(ctx);
router.send_message(&recipient_id, b"Hello").await?;
```

### Java

```java
SibnaClient client = new SibnaClient("https://sibna.example.com");
IdentityKeyPair identity = client.generateIdentity();
String token = client.authenticate();
DoubleRatchet session = client.createSession(peerId, peerBundle);
byte[] ct = session.encrypt("hello".getBytes());
```

Full API in [`sdks/java/README.md`](sdks/java/README.md).

### Go

```go
client, _ := sibna.NewClient("https://sibna.example.com", "/etc/sibna/server.pem")
id, _ := sibna.GenerateIdentity()
client.SetIdentity(id)
client.Authenticate()
client.SendMessage("<recipient-hex>", "<payload-hex>", true)
```

Full API in [`sdks/go/README.md`](sdks/go/README.md).

### JavaScript / TypeScript

```typescript
const client = new SibnaClient('https://sibna.example.com', { pinnedCertPath: './server.pem' });
await client.generateIdentity();
await client.authenticate();
await client.sendMessage({ recipientId: '<hex>', payloadHex: '<hex>' });
```

Full API in [`sdks/javascript/README.md`](sdks/javascript/README.md).

### Python

```python
client = SibnaClient(server="https://sibna.example.com", pinned_cert="/etc/sibna/server.pem")
client.generate_identity()
client.authenticate()
client.send_message(recipient_id="<hex>", payload_hex="<hex>")
```

Full API in [`sdks/python/README.md`](sdks/python/README.md).

### Dart

```dart
await SibnaProtocol.initialize();
final ctx = await SibnaContext.create();
final key = SibnaCrypto.generateKey();
final ct  = SibnaCrypto.encrypt(key, Uint8List.fromList(utf8.encode('hello')));
```

Full API in [`sdks/dart/README.md`](sdks/dart/README.md).

### Flutter

```dart
await SibnaFlutter.initialize();
final ctx = await SibnaContext.create();
final session = await ctx.createSession(peerId);
final ct = await session.encrypt(plaintext, associatedData: header);
```

Full API in [`sdks/flutter/README.md`](sdks/flutter/README.md).

### C++

```cpp
auto ctx = sibna::Context::create().value();
auto id  = ctx->generate_identity().value();
auto group = ctx->create_group(random_group_id).value();
auto sn   = sibna::SafetyNumber::calculate(my_pub, their_pub).value();
```

Full API in [`sdks/cpp/README.md`](sdks/cpp/README.md).

## Quick Start (Rust Core)

```toml
[dependencies]
sibna-core = { version = "3.0.1", features = ["pqc", "p2p"] }
```

```rust
use sibna_core::{SecureContext, Config};

let ctx = SecureContext::new(Config::default(), Some(b"MasterPassword"))?;
let identity = ctx.generate_identity()?;
let mut router = HybridRouter::new(ctx);
router.send_message(&recipient_id, b"Hello").await?;
```

## Quick Start (Java)

```java
SibnaClient client = new SibnaClient("https://sibna.example.com");
IdentityKeyPair identity = client.generateIdentity();
String token = client.authenticate();
DoubleRatchet session = client.createSession(peerId, peerBundle);
byte[] ct = session.encrypt("hello".getBytes());
```

Full API in [`sdks/java/README.md`](sdks/java/README.md).

## Quick Start (Go)

```go
client, _ := sibna.NewClient("https://sibna.example.com", "/etc/sibna/server.pem")
id, _ := sibna.GenerateIdentity()
client.SetIdentity(id)
client.Authenticate()
client.SendMessage("<recipient-hex>", "<payload-hex>", true)
```

Full API in [`sdks/go/README.md`](sdks/go/README.md).

## Quick Start (JavaScript / TypeScript)

```typescript
const client = new SibnaClient('https://sibna.example.com', { pinnedCertPath: './server.pem' });
await client.generateIdentity();
await client.authenticate();
await client.sendMessage({ recipientId: '<hex>', payloadHex: '<hex>' });
```

Full API in [`sdks/javascript/README.md`](sdks/javascript/README.md).

## Quick Start (Python)

```python
client = SibnaClient(server="https://sibna.example.com", pinned_cert="/etc/sibna/server.pem")
client.generate_identity()
client.authenticate()
client.send_message(recipient_id="<hex>", payload_hex="<hex>")
```

Full API in [`sdks/python/README.md`](sdks/python/README.md).

## Quick Start (Dart/Flutter)

```dart
await SibnaProtocol.initialize();
final ctx = await SibnaContext.create();
final key = SibnaCrypto.generateKey();
final ct  = SibnaCrypto.encrypt(key, Uint8List.fromList(utf8.encode('hello')));
```

Full API in [`sdks/dart/README.md`](sdks/dart/README.md) / [`sdks/flutter/README.md`](sdks/flutter/README.md).

## Quick Start (C++)

```cpp
auto ctx = sibna::Context::create().value();
auto id  = ctx->generate_identity().value();
auto group = ctx->create_group(random_group_id).value();
auto sn   = sibna::SafetyNumber::calculate(my_pub, their_pub).value();
```

Full API in [`sdks/cpp/README.md`](sdks/cpp/README.md).

## Security

- **Threat model**: see [`THREAT_MODEL.md`](THREAT_MODEL.md).
- **Security policy**: see [`SECURITY.md`](SECURITY.md).

Sibna is an **experimental research prototype**. It has **not** undergone independent third-party cryptographic review or formal security audit.

## Network Anonymity (Optional)

Sibna Core provides two optional anonymity layers that you can opt into.
**They are not enabled by default** and they have explicit limitations
that callers must understand before relying on them.

| Feature | How to enable | Verified? |
|---|---|---|
| SOCKS5 / Tor proxying (all HTTP + WebSocket) | `Config::proxy_url = Some("socks5://127.0.0.1:9050")` | ✅ wired (`core/src/transport/relay.rs:5,37,42-50`, `core/src/p2p/transport.rs:9,55`); requires an external Tor daemon |
| Cover traffic (Poisson process) | `HybridRouter::set_cover_traffic(true)` + `start_cover_traffic_loop(min, max)` | ✅ working post-SIBNA-2026-001 patch; requires the `p2p` feature flag and an active relay client |

**Limitations (read before relying on these features):**

- **mDNS peer discovery broadcasts random session tokens in cleartext on the LAN.** SIBNA-2026-029 replaced the static peer ID with a per-session random token, but the token is still sent unencrypted on the local network. Tor protects relay traffic only; mDNS leaks local peer presence to anyone on the same broadcast domain.
- **Cover traffic requires the `p2p` feature flag and an active relay client.** `start_cover_traffic_loop` is a no-op without `p2p`; calls to `set_cover_traffic(true)` without a relay client produce no cover traffic at all.
- **Tor is not bundled and not required.** You provide your own Tor daemon; Sibna does not start it, verify the circuit, or detect deanonymisation. Setting `proxy_url` to a SOCKS5 proxy that is not Tor reduces your anonymity to whatever that proxy provides.
- **Cover traffic does NOT protect against endpoint traffic analysis.** Local side-channels (process scheduling, OS-level telemetry, memory access patterns) are out of scope.
- **Only the Rust core exposes SOCKS5 configuration.** The Python, JavaScript, and Go SDKs do not currently support `proxy_url`. Java has TLS pinning but no SOCKS5. Dart and Flutter are FFI bindings to the Rust core, so they inherit whatever the host native library is configured with.
- **Cover traffic is a CRITICAL pre-audit hardening, not a formal guarantee.** SIBNA-2026-001 originally disabled cover traffic by rejecting empty plaintext in `CryptoHandler::encrypt`; the fix added SIBNA-2026-018 to randomise the per-block suffix length. The result is much harder to fingerprint, but has not been quantitatively evaluated against a state-level adversary model.

## Documentation index

- [`PROTOCOL_SPECIFICATION.md`](PROTOCOL_SPECIFICATION.md) — wire formats, X3DH transcript, padding block, ratchet state layout.
- [`SECURITY.md`](SECURITY.md) — public security policy and how to report vulnerabilities.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — attacker model, mitigations, residual risks.
- [`CHANGELOG.md`](CHANGELOG.md) — release history.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution rules.

## License

Apache License 2.0 / MIT (dual).
