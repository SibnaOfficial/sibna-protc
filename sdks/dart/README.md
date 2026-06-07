# Sibna Protocol — Dart SDK

> **Sibna Protocol v3.0.1** — Dart bindings to the native Sibna core via `dart:ffi`. Pure-server-side Dart, also usable from command-line Dart applications.
> This document reflects the code that is actually shipped in `sdks/dart/`. Anything not listed below is not implemented in this SDK.

## What this SDK is

The Dart SDK is a **thin FFI wrapper** around the native `libsibna` shared library. It uses `dart:ffi` to call into the Rust core. Anything that has not been wired through the FFI layer in `lib/src/bindings.dart` cannot be called from Dart.

What is implemented in `sdks/dart/lib/`:

| Capability | Implemented? | FFI symbol |
|---|---|---|
| Library load + initialisation | ✅ | `SibnaProtocol.initialize` |
| Native version query | ✅ | `sibna_version` |
| Context create / destroy | ✅ | `sibna_context_create`, `sibna_context_destroy` |
| Set device-link credentials | ✅ | `sibna_context_set_device_link` |
| Session create / destroy | ✅ | `sibna_session_create`, `sibna_session_destroy` |
| **Session encrypt / decrypt** | ❌ throws `UnimplementedError` | `sibna_session_encrypt` / `sibna_session_decrypt` are **not yet exported** by the Rust core. `SibnaSession.encrypt()` and `.decrypt()` will throw until the native symbols are added. |
| **Identity generate / sign / verify** | ❌ throws `UnimplementedError` | `sibna_identity_generate` / `sibna_identity_sign` / `sibna_identity_verify` are not declared in this binding. `SibnaContext.generateIdentity()` throws. |
| Standalone encrypt / decrypt (ChaCha20-Poly1305) | ✅ | `sibna_encrypt`, `sibna_decrypt` |
| Key generation (32 bytes) | ✅ | `sibna_generate_key` |
| Random bytes (any length) | ✅ | `sibna_random_bytes` |
| Buffer free | ✅ | `sibna_free_buffer` |
| **Group create / destroy** | ❌ throws `UnimplementedError` | `sibna_group_create` / `sibna_group_destroy` are not declared in this binding. `SibnaContext.createGroup()` returns a Dart-only stub that does not call the native side. |
| Safety number | ✅ (Dart implementation) | `SibnaSafetyNumber` — see below |
| Constants | ✅ | `sibnaVersion`, `protocolVersion`, `minCompatibleVersion`, `keyLength`, `nonceLength`, `tagLength`, `maxMessageSize` |

> **Read this carefully**: the Dart SDK exposes the *shape* of the API for sessions, identities, and groups, but several methods throw `UnimplementedError` because the FFI symbols are not yet exported by the Rust core. The methods that are safe to call today are `SibnaContext.create()`, `dispose()`, `setDeviceLink()`, `SibnaCrypto.encrypt()`, `SibnaCrypto.decrypt()`, `SibnaCrypto.generateKey()`, `SibnaCrypto.randomBytes()`, and `SibnaSafetyNumber.calculate()`. Anything else that is not on this list will throw.

## Requirements

- Dart 3.0+
- A `libsibna` shared library on the host:
  - `libsibna.so` (Linux, Android)
  - `libsibna.dylib` (macOS, iOS)
  - `sibna.dll` (Windows)

The SDK searches for the library in the current directory, the parent directory, and platform-specific system paths (`/usr/local/lib`, `/usr/lib`, `C:\Windows\System32`).

## Installation

```yaml
# pubspec.yaml of your Dart app
dependencies:
  sibna_protocol:
    path: sdks/dart
```

The package is not currently published to pub.dev. Use it from this source tree.

## Module layout

```
sdks/dart/
├── lib/
│   ├── sibna_protocol.dart   # main library
│   └── src/
│       ├── bindings.dart     # FFI symbols
│       ├── context.dart      # SibnaContext
│       ├── session.dart      # SibnaSession
│       ├── identity.dart     # IdentityKeyPair, PreKeyBundle
│       ├── crypto.dart       # SibnaCrypto (encrypt/decrypt)
│       ├── errors.dart       # SibnaError, SibnaErrorCode
│       ├── utils.dart        # SibnaUtils (hex, constant-time, secure clear)
│       ├── group.dart        # SibnaGroup, GroupMessage (Dart-side stub)
│       └── safety_number.dart  # SibnaSafetyNumber (Dart implementation)
├── test/
├── pubspec.yaml
└── README.md
```

The library is a single `library sibna_protocol` that exposes all parts.

## Quick start

```dart
import 'package:sibna_protocol/sibna_protocol.dart';
import 'dart:ffi';
import 'dart:typed_data';

Future<void> main() async {
  // 1. Initialize once. Auto-detects libsibna.so / .dylib / .dll.
  await SibnaProtocol.initialize();

  // 2. Create a secure context.
  final ctx = await SibnaContext.create(password: 'correct horse battery staple');

  // 3. Generate a random 32-byte key and encrypt a message.
  final key = SibnaCrypto.generateKey();
  final ct  = SibnaCrypto.encrypt(key, Uint8List.fromList(utf8.encode('hello')));
  final pt  = SibnaCrypto.decrypt(key, ct);
  assert(utf8.decode(pt) == 'hello');

  // 4. Set up a multi-device link.
  await ctx.setDeviceLink(
    deviceId: 1,
    rootKey:  Uint8List(32),       // 32 bytes from another device
    signature: Uint8List(64),      // Ed25519 signature over (device_identity_key || device_id)
  );

  // 5. Calculate a safety number with a peer (Dart-side, no FFI).
  final ours   = Uint8List.fromList(List.generate(32, (i) => i));
  final theirs = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final sn = SibnaSafetyNumber.calculate(ours, theirs);
  print(sn.formatted);   // 16 groups of 5 decimal digits

  // 6. Always dispose.
  ctx.dispose();
  SibnaProtocol.cleanup();
}
```

## API reference

### `class SibnaProtocol`

| Static member | Description |
|---|---|
| `SibnaProtocol.initialize({String? libraryPath})` | Load `libsibna`. Idempotent. |
| `SibnaProtocol.isInitialized` | `true` after `initialize()`. |
| `SibnaProtocol.lib` | The loaded `DynamicLibrary`. Throws if not initialised. |
| `SibnaProtocol.version` | Calls `sibna_version`. Falls back to the hard-coded `sibnaVersion` string if the FFI call fails. |
| `SibnaProtocol.cleanup()` | Unload the library. |

### `class SibnaContext`

| Method | Description | FFI? |
|---|---|---|
| `SibnaContext.create({String? password})` | Calls `sibna_context_create`. The password buffer is zeroed in native memory after the call. | ✅ |
| `setDeviceLink({int deviceId, Uint8List rootKey, Uint8List signature})` | Calls `sibna_context_set_device_link`. | ✅ |
| `generateIdentity()` | **Throws `UnimplementedError`**. The FFI binding for `sibna_identity_generate` is not declared. | ❌ |
| `createSession(Uint8List peerId)` | Calls `sibna_session_create`. | ✅ |
| `encryptMessage(peerId, plaintext, {associatedData})` | **Throws `UnimplementedError`**. A previous version of this method generated a fresh random key per call, which would have produced undecryptable ciphertext. It is now stubbed until the native encrypt function is wired up. | ❌ |
| `decryptMessage(peerId, ciphertext, {associatedData})` | Looks up the session by peer ID and delegates to `session.decrypt`. Throws `SessionNotFound` if no session exists. | ✅ (forwards) |
| `createGroup(Uint8List groupId)` | Returns a Dart-side `SibnaGroup` object — the FFI binding for `sibna_group_create` is **not** declared in this version. The group object lives in pure Dart; no native handle is created. | ❌ (Dart-only) |
| `getStats()` | Returns a hard-coded map with `version`, `sessionCount: 0`, `groupCount: 0`, and `createdAt`. The native stats query is not exposed. | ❌ |
| `dispose()` | Calls `sibna_context_destroy`. | ✅ |
| `isDisposed` | `true` after `dispose()`. |  |

### `class SibnaSession`

| Method | Description | FFI? |
|---|---|---|
| `SibnaSession.fromSharedSecret(sharedSecret, localDh, remoteDh, config, role)` | Factory constructor used for testing — does **not** call into the native library. | ❌ |
| `performHandshake(PreKeyBundle peerBundle, {required bool initiator})` | Dart-side stub. Marks the session as established; does not perform any X3DH math. | ❌ |
| `encrypt(plaintext, {associatedData})` | **Throws `UnimplementedError`** if no native handle is present. The binding for `sibna_session_encrypt` is not declared in this version. | ❌ |
| `decrypt(ciphertext, {associatedData})` | Same as `encrypt`. | ❌ |
| `currentMessageNumber`, `messagesSent`, `messagesReceived`, `establishedAt`, `isEstablished`, `age`, `stats` | Accessors backed by Dart-side counters. |  |
| `dispose()` | Calls `sibna_session_destroy` if a handle is present. | ✅ |

### `class SibnaGroup` (Dart-side stub)

The `SibnaGroup` class exists in the public API but its `encrypt` and `decrypt` methods operate on a per-message sender key generated with `SibnaCrypto.generateKey()`. There is no native group state. The class supports:

- `addMember(publicKey)` / `removeMember(publicKey)` — Dart-side list management.
- `importSenderKey(memberPublicKey, senderKey)` — Dart-side map of public key → 32-byte sender key.
- `encrypt(plaintext)` — generates a per-message sender key, encrypts with `SibnaCrypto.encrypt`, returns a `GroupMessage`.
- `decrypt(message, senderPublicKey)` — looks up the sender's key and calls `SibnaCrypto.decrypt`.
- `leave()` — clears all keys.
- `GroupMessage.toBytes()` / `GroupMessage.fromBytes()` — wire format: `group_id(32) ‖ sender_key_id(4, LE) ‖ message_number(4, LE) ‖ ciphertext_len(4, LE) ‖ ciphertext ‖ epoch(4, LE) ‖ timestamp(8, LE)`.

This implementation is sufficient for round-trip testing but is **not** interoperable with the native group's state format.

### `class SibnaCrypto` (FFI-backed)

| Method | Description |
|---|---|
| `generateKey() → Uint8List` | 32 bytes from `sibna_generate_key`. |
| `randomBytes(int length) → Uint8List` | `length` bytes from `sibna_random_bytes` (1 … 1 048 576). |
| `encrypt(key, plaintext, {associatedData}) → Uint8List` | ChaCha20-Poly1305. Returns `nonce(12) ‖ ciphertext ‖ tag(16)`. Validates `key.length == 32`, `plaintext.length in [1, 10 MiB]`. |
| `decrypt(key, ciphertext, {associatedData}) → Uint8List` | ChaCha20-Poly1305. Throws `SibnaError(authenticationFailed)` on tag mismatch. |

### `class SibnaSafetyNumber`

```dart
final sn = SibnaSafetyNumber.calculate(ourKey32, theirKey32);
print(sn.formatted);   // 16 groups of 5 decimal digits (e.g. "12345 67890 …")
sn.matches(otherSn);    // constant-time fingerprint equality
```

Algorithm:

1. Sort the two 32-byte keys lexicographically (`first` ≤ `second`).
2. `SHA-512( 0x01 ‖ "SIBNA_SAFETY_NUMBER_V1" (utf-8) ‖ first ‖ second )`.
3. Use the first 32 bytes of the digest as the fingerprint. Format as 16 decimal 5-digit groups separated by spaces.
4. Equality is verified over the 32-byte fingerprint in constant time.

This Dart implementation is deterministic on both sides and matches the algorithm in the Rust core's `safety_number` module. There is no FFI call involved.

### `class SibnaUtils`

Hex encoding, constant-time byte comparison, and a `secureClear` extension on `Uint8List` that fills the buffer with zeros.

### Error model

`SibnaErrorCode` mirrors the FFI error codes:

| Code | Meaning |
|---|---|
| `0` | `ok` |
| `1` | `invalidArgument` |
| `2` | `invalidKey` |
| `3` | `encryptionFailed` |
| `4` | `decryptionFailed` |
| `5` | `outOfMemory` |
| `6` | `invalidState` |
| `7` | `sessionNotFound` |
| `8` | `keyNotFound` |
| `9` | `rateLimitExceeded` |
| `10` | `internalError` |
| `11` | `bufferTooSmall` |
| `12` | `invalidCiphertext` |
| `13` | `authenticationFailed` |
| `100` | `libraryNotFound` |
| `101` | `notInitialized` |

`SibnaError` carries the code and a human-readable message.

## Security notes

- The password passed to `SibnaContext.create()` is zeroed in native memory immediately after the FFI call. The Dart-side `Uint8List` is not zeroed — copy the password into a freshly allocated list, hand it to the FFI, then `secureClear` the Dart copy.
- `SibnaCrypto.encrypt` and `SibnaCrypto.decrypt` accept only 32-byte keys and validate against all-zero keys.
- `SibnaSafetyNumber.matches` is constant-time over the 32-byte fingerprint.
- Random bytes come from the native CSPRNG via `sibna_random_bytes`.
- All buffers that are copied into native memory (`keyPtr`, `ptPtr`, `adPtr`) are zeroed before being freed in the `finally` block.

## Limitations

- The Dart SDK is **not** a complete end-to-end encryption library at this version. The class shapes for `SibnaSession.encrypt`, `SibnaContext.generateIdentity`, and `SibnaGroup` exist but the corresponding native symbols are not yet exported from the Rust core. These methods throw `UnimplementedError`.
- The Dart `SibnaGroup` is a pure-Dart fallback — it cannot interoperate with the native `GroupSession` state format.
- The `SibnaSession.fromSharedSecret` factory and `SibnaSession.performHandshake` are stubs intended for testing only.
- The package is not currently published to pub.dev.

## License

Apache-2.0 OR MIT
