# Sibna Protocol — C++ SDK

> **Sibna Protocol v3.0.1** — pure C++17 implementation with OpenSSL 3.x as the only system dependency. No Rust, no FFI. Build a shared or static library and link it from your application.
> This document reflects the code that is actually shipped in `sdks/cpp/`. Anything not listed below is not implemented in this SDK.

## What this SDK is

The C++ SDK is a **native, self-contained** implementation of the Sibna cryptographic core. It is the most complete language binding in this repository: it implements X3DH-style handshake, group messaging with sender keys, and an out-of-band identity verification flow with safety numbers and QR codes — all in C++ on top of OpenSSL.

What is implemented in `sdks/cpp/`:

| Capability | Implemented? | Notes |
|---|---|---|
| Ed25519 identity keypair | ✅ | `IdentityKeyPair::generate` (OpenSSL `EVP_PKEY_ED25519`) |
| X25519 identity keypair (separate from Ed25519) | ✅ | Constructed alongside the Ed25519 keypair in `generate()`. |
| Ed25519 sign / verify | ✅ | `IdentityKeyPair::sign`, `verify` |
| PreKey bundle (signed prekey, optional OTP, 7-day expiry) | ✅ | `PreKeyBundle` with `to_bytes` / `from_bytes` / `verify_signature` |
| ChaCha20-Poly1305 AEAD (RFC 8439, 12-byte nonce) | ✅ | `Crypto::encrypt` / `decrypt`. Wire format: `nonce(12) ‖ ciphertext ‖ tag(16)`. |
| SHA-256, HMAC-SHA-256 | ✅ | `Crypto::sha256`, `Crypto::hmac_sha256` |
| `SecureRandom` from OpenSSL CSPRNG | ✅ | `Crypto::generate_key`, `Crypto::random_bytes` |
| `Context` (per-application state, holds sessions and groups) | ✅ | `Context::create` |
| `Session` (per-peer, session-key based) | ✅ | `Session::encrypt` / `decrypt` / `perform_handshake` |
| `GroupSession` (sender keys, members, epoch) | ✅ | `GroupSession::add_member` / `remove_member` / `encrypt` / `decrypt` |
| `GroupMessage` (binary serialisation) | ✅ | `GroupMessage::to_bytes` / `from_bytes`. 24-hour expiry. |
| `SafetyNumber` (out-of-band identity verification) | ✅ | `SafetyNumber::calculate`, `parse`, `qr_data`, `verify`, `similarity` |
| `VerificationQrCode` (binary, for QR encoding) | ✅ | `VerificationQrCode::to_bytes` / `from_bytes` |
| `compare_safety_numbers` (MATCH / SIMILAR / MISMATCH) | ✅ | threshold default 0.8 |
| Base64 utilities | ✅ | `Utils::bytes_to_base64`, `base64_to_bytes` |
| Fingerprint (SHA-256, 8 bytes → 16 hex chars) | ✅ | `Utils::calculate_fingerprint` |
| Safety number formatting (5-digit groups) | ✅ | `Utils::format_safety_number` |
| `Result<T>` return type with error code | ✅ | `error.hpp` |

What is **not** implemented in the C++ SDK:

- ❌ TLS certificate pinning — there is no HTTP transport in this SDK. The C++ SDK is the cryptographic core, not a relay client.
- ❌ HTTP / WebSocket transport — none.
- ❌ Double Ratchet ratchet step (DH ratchet) — the `Session` class uses a session key directly and does not implement the per-message DH ratchet step.
- ❌ X3DH handshake (initiator/responder symmetry) — `Session::perform_handshake` validates the bundle signature and stores the peer, but it does not perform the 3-4 DH operations.

## Requirements

- A C++17 compiler (GCC 9+, Clang 10+, MSVC 2019+).
- OpenSSL 3.x (development headers and the `libcrypto` library).
- CMake 3.14 or newer.

The CMake build adds `pthread`, `-Wall -Wextra -Wpedantic` on GCC/Clang and `/W4 /permissive- /sdl /guard:cf /DYNAMICBASE /NXCOMPAT` on MSVC.

## Building

```bash
cd sdks/cpp
mkdir build && cd build
cmake -DSIBNA_BUILD_TESTS=ON -DSIBNA_BUILD_EXAMPLES=ON ..
cmake --build . -j
ctest --output-on-failure
```

CMake options:

| Option | Default | Effect |
|---|---|---|
| `SIBNA_BUILD_TESTS` | ON | Build the unit tests in `tests/`. |
| `SIBNA_BUILD_EXAMPLES` | ON | Build the example programs in `examples/`. |
| `SIBNA_BUILD_SHARED` | ON | Build a shared library. Set to OFF to build static. |
| `SIBNA_ENABLE_ASAN` | OFF | Build with AddressSanitizer (`-fsanitize=address`). |

The build produces `libsibna.so` / `libsibna.dylib` / `sibna.dll` (or `libsibna.a` for static). The CMake package config is installed to `${CMAKE_INSTALL_LIBDIR}/cmake/sibna_protocol/`.

## Module layout

```
sdks/cpp/
├── include/sibna/
│   ├── sibna.hpp          # umbrella header
│   ├── context.hpp        # Context
│   ├── session.hpp        # Session
│   ├── crypto.hpp         # Crypto
│   ├── identity.hpp       # IdentityKeyPair, PreKeyBundle
│   ├── group.hpp          # GroupSession, GroupMessage
│   ├── safety_number.hpp  # SafetyNumber, VerificationQrCode
│   ├── utils.hpp          # Utils (base64, fingerprint, formatting)
│   ├── error.hpp          # Result<T>, ResultCode, SibnaError
│   └── types.hpp          # bytes, key, nonce, signature, group_id, device_id
├── src/
│   ├── context.cpp
│   ├── session.cpp
│   ├── crypto.cpp
│   ├── identity.cpp
│   ├── group.cpp
│   ├── safety_number.cpp
│   ├── utils.cpp
│   └── error.cpp
├── tests/                 # CTest unit tests
├── examples/              # Example programs
├── CMakeLists.txt
└── README.md
```

Everything is in the `sibna` namespace.

## Quick start

```cpp
#include <sibna/sibna.hpp>
#include <iostream>

int main() {
    // 1. Create a context.
    auto ctx_res = sibna::Context::create();
    if (ctx_res.is_err()) {
        std::cerr << ctx_res.message() << "\n";
        return 1;
    }
    auto& ctx = ctx_res.value();

    // 2. Generate an Ed25519 + X25519 identity.
    auto id_res = ctx->generate_identity();
    if (id_res.is_err()) {
        std::cerr << id_res.message() << "\n";
        return 1;
    }
    auto identity = id_res.value();

    // 3. Standalone AEAD.
    auto key_res = sibna::Crypto::generate_key();
    auto pt = std::vector<uint8_t>{'h','e','l','l','o'};
    auto ct_res = sibna::Crypto::encrypt(key_res.value(), pt);
    auto dec_res = sibna::Crypto::decrypt(key_res.value(), ct_res.value());

    // 4. Create a group with a random 32-byte group ID.
    auto group_id = sibna::Utils::random_bytes(32).value();
    auto group = ctx->create_group(group_id).value();

    // 5. Safety number with another identity.
    auto peer_pub = sibna::Utils::random_bytes(32).value();
    auto sn = sibna::SafetyNumber::calculate(identity.ed25519_public_key(), peer_pub).value();
    std::cout << "Safety number: " << sn.formatted_number() << "\n";

    return 0;
}
```

## API reference

### `class Context`

```cpp
class Context {
public:
    static Result<std::unique_ptr<Context>> create(
        const Config& config = Config{},
        const std::optional<std::string>& password = std::nullopt);

    Result<IdentityKeyPair> generate_identity();

    Result<std::unique_ptr<Session>> create_session(const bytes& peer_id);
    Result<bytes> encrypt_message(const bytes& peer_id, const bytes& plaintext,
                                  const bytes& associated_data = {});
    Result<bytes> decrypt_message(const bytes& peer_id, const bytes& ciphertext,
                                  const bytes& associated_data = {});

    Result<std::unique_ptr<GroupSession>> create_group(const group_id& id);

    struct Stats { size_t session_count; size_t group_count;
                   std::string version;
                   std::chrono::system_clock::time_point created_at; };
    Result<Stats> get_stats() const;
    bool is_healthy() const;
};
```

`Config` (see `types.hpp`):

| Field | Default | Effect |
|---|---|---|
| `max_skipped_messages` | 2000 | Hard-capped at 10000. Above that, `create()` fails. |
| `session_timeout_secs` | 1800 | Sessions older than this without activity are reported as not healthy. |

`Context` is non-copyable and non-movable (sessions and groups hold raw pointers into the context).

### `class Session`

```cpp
class Session {
public:
    Result<void> perform_handshake(const PreKeyBundle& peer_bundle, bool initiator);
    Result<bytes> encrypt(const bytes& plaintext, const bytes& associated_data = {});
    Result<bytes> decrypt(const bytes& ciphertext, const bytes& associated_data = {});
    size_t current_message_number() const;
    bool is_established() const;
    std::optional<std::chrono::seconds> age() const;
    SessionInfo get_stats() const;
};
```

The `Session` constructor generates a fresh 32-byte session key. `perform_handshake` validates the peer's prekey bundle (signature, expiry) and stamps the session as established. Subsequent `encrypt` / `decrypt` calls use that session key directly — there is no per-message DH ratchet in this revision.

`encrypt` rejects empty plaintexts. `decrypt` rejects ciphertexts shorter than `nonce + tag + 1` (29 bytes).

### `class GroupSession`

```cpp
class GroupSession {
public:
    static constexpr size_t MAX_GROUP_SIZE = 256;

    Result<void> add_member(const std::array<byte, 32>& public_key);
    Result<void> remove_member(const std::array<byte, 32>& public_key);
    Result<void> import_sender_key(const std::array<byte, 32>& member_public_key,
                                   const key& sender_key);
    Result<GroupMessage> encrypt(const bytes& plaintext);
    Result<bytes> decrypt(const GroupMessage& message,
                          const std::array<byte, 32>& sender_public_key);
    Result<void> leave();
    GroupInfo get_info() const;
};
```

`MAX_GROUP_SIZE` is 256 members. `decrypt` rejects expired messages (older than 24 hours) and messages for a different group ID. `leave` increments the epoch and clears all sender keys.

### `class GroupMessage`

```cpp
class GroupMessage {
public:
    bytes to_bytes() const;
    static Result<GroupMessage> from_bytes(const bytes& data);
    bool is_expired() const;   // 24 hours
};
```

Wire format: `group_id(32) ‖ sender_key_id(4, LE) ‖ message_number(4, LE) ‖ ciphertext_len(4, LE) ‖ ciphertext ‖ epoch(8, LE) ‖ timestamp(8, LE)`.

### `class IdentityKeyPair`

```cpp
class IdentityKeyPair {
public:
    static Result<IdentityKeyPair> generate();
    Result<signature> sign(const bytes& data) const;
    Result<bool> verify(const bytes& data, const signature& sig) const;
    void clear_private_keys();
    const std::array<byte, 32>& ed25519_public_key() const;
    const std::array<byte, 32>& x25519_public_key() const;
    const std::string& fingerprint() const;       // 16 hex chars (first 8 bytes of SHA-256)
};
```

The Ed25519 public key is generated first; the X25519 keypair is generated independently afterwards. The constructor stores the fingerprint computed from the Ed25519 public key. `clear_private_keys` zeros both private keys.

### `class PreKeyBundle`

```cpp
class PreKeyBundle {
public:
    static PreKeyBundle create(/* … */);
    bytes to_bytes() const;
    static Result<PreKeyBundle> from_bytes(const bytes& data);
    bool is_expired() const;       // 7 days
    Result<bool> verify_signature(const std::array<byte, 32>& identity_public_key) const;
};
```

Wire format: `identity_key(32) ‖ signed_prekey(32) ‖ signature(64) ‖ has_otp(1) ‖ otp?(32) ‖ timestamp(8, LE)`.

### `class Crypto`

```cpp
class Crypto {
public:
    static Result<key> generate_key();
    static Result<bytes> random_bytes(size_t length);
    static Result<bytes> encrypt(const key& key, const bytes& plaintext,
                                 const bytes& associated_data = {});
    static Result<bytes> decrypt(const key& key, const bytes& ciphertext,
                                 const bytes& associated_data = {});
    static Result<bytes> sha256(const bytes& data);
    static Result<bytes> hmac_sha256(const key& key, const bytes& data);
};
```

`encrypt` rejects empty plaintexts and produces `nonce(12) ‖ ciphertext ‖ tag(16)`. `decrypt` rejects ciphertexts shorter than 29 bytes. Both use RFC 8439 ChaCha20-Poly1305 (12-byte nonce) with the two-phase OpenSSL initialisation.

### `class SafetyNumber` and `class VerificationQrCode`

```cpp
class SafetyNumber {
public:
    static Result<SafetyNumber> calculate(
        const std::array<byte, 32>& our_identity,
        const std::array<byte, 32>& their_identity);
    static Result<SafetyNumber> parse(const std::string& safety_number);

    const std::string& formatted_number() const;   // 12 groups of 5 hex chars
    const std::array<byte, 32>& fingerprint() const;
    bytes qr_data() const;                          // version(1) ‖ fingerprint(32)
    bool verify(const SafetyNumber& other) const;   // constant-time
    double similarity(const SafetyNumber& other) const;
    int version() const;
};
```

`SafetyNumber::calculate` is **order-independent** — the two identities are sorted lexicographically before hashing. The algorithm is:

1. Sort the two 32-byte keys lexicographically.
2. `SHA-512( 0x01 ‖ first ‖ second )`.
3. Use the first 32 bytes of the digest as the fingerprint, formatted as 12 groups of 5 hex characters (60 hex chars total).

`SafetyNumber::parse` accepts the same 60-hex-char string (with optional spaces) and re-builds the fingerprint.

`VerificationQrCode` carries:

- `identity_key(32)`,
- `device_id(16)`,
- `safety_fingerprint(32)`,
- `verified: bool`.

Wire format: `version(1) ‖ identity_key(32) ‖ device_id(16) ‖ safety_fingerprint(32) ‖ verified(1)`.

```cpp
enum class SafetyComparison { MATCH, SIMILAR, MISMATCH };
SafetyComparison compare_safety_numbers(
    const SafetyNumber& a, const SafetyNumber& b,
    double similarity_threshold = 0.8);
```

### `class Utils`

```cpp
class Utils {
public:
    static std::string bytes_to_base64(const bytes& data);
    static bytes base64_to_bytes(const std::string& base64);
    static std::string calculate_fingerprint(const bytes& public_key);  // 16 hex chars
    static std::string format_safety_number(const std::string& safety_number);
    static bool constant_time_equals(const bytes& a, const bytes& b);
    static int  compare_bytes(const std::array<byte, 32>& a, const std::array<byte, 32>& b);
    static void secure_clear(bytes& data);
    static Result<bytes> random_bytes(size_t length);
    static void validate_key_length(const key& key);
    static void validate_message_size(const bytes& data);
};
```

### `class Result<T>` and `enum class ResultCode`

```cpp
template <typename T>
class Result {
public:
    bool is_ok() const;
    bool is_err() const;
    ResultCode code() const;
    const std::string& message() const;
    T& value();
    const T& value() const;
    template <typename U> T value_or(U&& default_value) const;
};

enum class ResultCode {
    OK = 0,
    INVALID_ARGUMENT = 1,
    INVALID_KEY = 2,
    ENCRYPTION_FAILED = 3,
    DECRYPTION_FAILED = 4,
    OUT_OF_MEMORY = 5,
    INVALID_STATE = 6,
    KEY_NOT_FOUND = 7,
    SESSION_NOT_FOUND = 8,
    RATE_LIMIT_EXCEEDED = 9,
    INTERNAL_ERROR = 10,
    BUFFER_TOO_SMALL = 11,
    INVALID_CIPHERTEXT = 12,
    AUTHENTICATION_FAILED = 13,
    VALIDATION_ERROR = 14,
};
```

`SibnaError` (a `std::runtime_error` subclass) carries the `ResultCode` and the message.

## Security notes

- All randomness comes from OpenSSL's CSPRNG (`RAND_bytes`).
- ChaCha20-Poly1305 uses RFC 8439 12-byte nonces. The two-phase OpenSSL initialisation is required to set the IV length correctly — the `crypt.cpp` comments document this.
- `IdentityKeyPair::verify` is constant-time within the OpenSSL provider (no early-exit in our wrapper).
- `Utils::constant_time_equals` is constant-time.
- `Utils::secure_clear` overwrites the buffer with zeros.
- The `Context` dtor and `Session` dtor both zero all key material they own. The `Context` dtor is invoked when the last `std::unique_ptr<Context>` is released.
- PreKey bundles expire after 7 days. Group messages expire after 24 hours.

## Limitations

- The C++ SDK is the **cryptographic core**. It does not include a relay client (no HTTP, no WebSocket, no TLS pinning).
- `Session` uses a single session key — there is no Double Ratchet ratchet step in this revision.
- `Session::perform_handshake` validates the bundle signature and stamps the session as established, but it does not perform the 3-4 X3DH DH operations. To interoperate with a full X3DH peer, run this SDK's `Context` together with the protocol's handshake state.
- The `SibnaError` class is the only exception type thrown; `Result<T>` is the preferred failure channel.
- The SDK has been built and tested on Linux with GCC and Clang. MSVC is configured in the CMake build (`/W4 /permissive- /sdl /guard:cf /DYNAMICBASE /NXCOMPAT`) but is not exercised in CI.

## License

Apache-2.0 OR MIT
