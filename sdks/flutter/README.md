# `sibna_flutter` — Flutter Plugin

> **Sibna Protocol v3.0.1** — Flutter plugin that bridges Dart to the Rust Sibna core via `dart:ffi`. Exposes X3DH, Double Ratchet, and group messaging primitives on Android, iOS, macOS, Windows, and Linux.
> This document reflects the code that is actually shipped in `sdks/flutter/`. Anything not listed below is not implemented in this plugin.

## What this plugin is

`SibnaFlutter` is a Flutter plugin that loads `libsibna` (the same native shared library used by the Dart SDK) and exposes a small Dart surface. Compared to the Dart SDK, this plugin has a **wider set of FFI symbols wired up** (session encrypt/decrypt, group create/destroy, identity generate/verify) and a tighter Dart wrapper.

What is implemented in `sdks/flutter/lib/`:

| Capability | Implemented? | FFI symbol |
|---|---|---|
| Library load + initialisation | ✅ | `SibnaFlutter.initialize` |
| Native version query | ✅ | `sibna_version` |
| Context create / destroy | ✅ | `sibna_context_create`, `sibna_context_destroy` |
| Session create / destroy | ✅ | `sibna_session_create`, `sibna_session_destroy` |
| **Session encrypt / decrypt** | ✅ | `sibna_session_encrypt`, `sibna_session_decrypt` — this is the difference from the Dart SDK: these are wired up. |
| Group create / destroy | ✅ | `sibna_group_create`, `sibna_group_destroy` |
| Identity generate | ✅ | `sibna_identity_generate` |
| Identity verify | ✅ | `sibna_identity_verify` |
| **Identity sign** | ❌ | `sibna_identity_sign` is **not** declared. The Dart `SibnaIdentity` class is a value type (public keys only) — it cannot sign. |
| **Identity destroy** | ✅ | `sibna_identity_destroy` is declared but no Dart wrapper currently calls it (Dart `SibnaIdentity` does not hold a native handle). |
| Standalone encrypt / decrypt (ChaCha20-Poly1305) | ✅ | `sibna_encrypt`, `sibna_decrypt` |
| Key generation (32 bytes) | ✅ | `sibna_generate_key` |
| Random bytes (any length) | ✅ | `sibna_random_bytes` |
| Buffer free | ✅ | `sibna_free_buffer` |
| Safety number | ✅ (Dart implementation) | `SibnaSafetyNumber` |
| Constants | ✅ | `sibnaVersion`, `protocolVersion`, `minCompatibleVersion`, `keyLength`, `nonceLength`, `tagLength`, `maxMessageSize` |

## Platform support

| Platform | Architecture | How the library is provided |
|---|---|---|
| Android | arm64-v8a, armeabi-v7a, x86_64 | bundled via the Gradle `externalNativeBuild` (FFI plugin: `true`); loaded with `DynamicLibrary.open('libsibna.so')`. |
| iOS | arm64, x86_64 (simulator) | statically linked into the framework; loaded with `DynamicLibrary.process()`. |
| macOS | arm64, x86_64 | bundled next to the executable (`<app>.app/Contents/Frameworks/libsibna.dylib`); falls back to `~/Library/Application Support/libsibna.dylib`. |
| Windows | x86_64 | bundled next to the executable (`sibna.dll`); falls back to `data/flutter_assets/sibna.dll` and the system PATH. |
| Linux | x86_64 | bundled at `<exe>/lib/libsibna.so` or `<exe>/libsibna.so`. |

The plugin throws `SibnaPluginError` if the platform is not supported or the library cannot be loaded.

## Requirements

- Flutter 3.x
- Dart 3.0+
- The native library must be present in the build output of the host application.

## Installation

```yaml
# pubspec.yaml
dependencies:
  sibna_flutter: ^3.0.1
```

The package is not currently published to pub.dev. Use it from this source tree.

## Module layout

```
sdks/flutter/
├── lib/
│   ├── sibna_flutter.dart        # public entry point
│   └── src/
│       ├── ffi_bindings.dart     # _SibnaBindings (all FFI symbols)
│       ├── sibna_flutter_base.dart  # SibnaFlutter (init, version, dispose)
│       ├── errors.dart           # SibnaErrorCode, SibnaError, SibnaValidationError
│       ├── crypto.dart           # SibnaCrypto (encrypt/decrypt/generate)
│       ├── context.dart          # SibnaContext
│       ├── session.dart          # SibnaSession
│       ├── identity.dart         # SibnaIdentity (value type, public keys only)
│       ├── safety_number.dart    # SibnaSafetyNumber
│       └── group.dart            # SibnaGroup, SibnaGroupMessage
├── test/
├── android/  ios/  linux/  macos/  windows/
├── example/
├── pubspec.yaml
└── README.md
```

## Quick start

```dart
import 'package:sibna_flutter/sibna_flutter.dart';
import 'dart:typed_data';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await SibnaFlutter.initialize();

  // 1. Create a context (optionally password-protected)
  final ctx = await SibnaContext.create(password: 'correct horse battery staple');

  // 2. Generate a session for a peer
  final session = await ctx.createSession(Uint8List.fromList(List.generate(32, (i) => i)));

  // 3. Encrypt / decrypt
  final ct = await session.encrypt(
    Uint8List.fromList(utf8.encode('hello')),
    associatedData: utf8.encode('header'),
  );
  final pt = await session.decrypt(ct, associatedData: utf8.encode('header'));
  assert(utf8.decode(pt) == 'hello');

  // 4. Standalone AEAD
  final key = SibnaCrypto.generateKey();
  final aead = SibnaCrypto.encrypt(key, Uint8List.fromList(utf8.encode('msg')));

  // 5. Safety number
  final sn = SibnaSafetyNumber.calculate(
    Uint8List.fromList(List.generate(32, (i) => i)),
    Uint8List.fromList(List.generate(32, (i) => i + 1)),
  );
  print(sn.formatted);

  // 6. Always dispose
  session.dispose();
  ctx.dispose();
}
```

## API reference

### `class SibnaFlutter`

| Static member | Description |
|---|---|
| `SibnaFlutter.initialize({String? libraryPath})` | Resolve and load the native library. Idempotent. Throws `SibnaPluginError` on failure. |
| `SibnaFlutter.isInitialized` | `true` after `initialize()`. |
| `SibnaFlutter.bindings` | Internal `_SibnaBindings` instance. Throws `SibnaNotInitializedError` if not initialised. |
| `SibnaFlutter.nativeVersion` | Calls `sibna_version`. |
| `SibnaFlutter.dispose()` | Unload the library. |

### `class SibnaContext`

| Method | Description |
|---|---|
| `SibnaContext.create({String? password})` | Calls `sibna_context_create`. The native password buffer is zeroed before the FFI returns. |
| `createSession(Uint8List peerId) → SibnaSession` | Calls `sibna_session_create`. |
| `dispose()` | Calls `sibna_context_destroy`. |
| `isDisposed` | `true` after `dispose()`. |

> This plugin's `SibnaContext` is narrower than the Dart SDK's. It does not expose `setDeviceLink`, `generateIdentity`, `createGroup`, `getStats`, or `encryptMessage`/`decryptMessage`. The only operations wired through are context create/destroy and session create/destroy.

### `class SibnaSession`

| Method | Description |
|---|---|
| `encrypt(plaintext, {associatedData}) → Future<Uint8List>` | Calls `sibna_session_encrypt`. Validates `plaintext.isNotEmpty` and `plaintext.length ≤ 10 MiB`. |
| `decrypt(ciphertext, {associatedData}) → Future<Uint8List>` | Calls `sibna_session_decrypt`. |
| `dispose()` | Calls `sibna_session_destroy`. |
| `peerId`, `messagesSent`, `messagesReceived`, `isDisposed` | Accessors. |

### `class SibnaGroup` (FFI-backed)

| Method | Description |
|---|---|
| `SibnaGroup.create() → SibnaGroup` | Generates a random 32-byte group ID via `sibna_random_bytes`, then calls `sibna_group_create`. |
| `dispose()` | Calls `sibna_group_destroy`. |
| `groupId`, `isDisposed` | Accessors. |

> The `SibnaGroup` API surface in this plugin is intentionally narrow: create, dispose, and accessors. The encrypt/decrypt/member-management methods that the Dart SDK exposes are not present here.

### `class SibnaCrypto`

Identical to the Dart SDK. Standalone ChaCha20-Poly1305 AEAD backed by the native primitives.

| Method | Description |
|---|---|
| `generateKey() → Uint8List` | 32 random bytes. |
| `randomBytes(int length) → Uint8List` | 1 … 1 048 576 random bytes. |
| `encrypt(key, plaintext, {associatedData}) → Uint8List` | ChaCha20-Poly1305. |
| `decrypt(key, ciphertext, {associatedData}) → Uint8List` | ChaCha20-Poly1305. |

### `class SibnaIdentity` (Dart value type)

```dart
class SibnaIdentity {
  final Uint8List ed25519Public;  // 32 bytes
  final Uint8List x25519Public;   // 32 bytes
  String get fingerprint;         // first 16 hex chars of SHA-256(ed25519 ‖ x25519)
  bool get isValid;               // length == 32, not all zeros
}
```

This is a **value object** in the current version: it holds the public keys only. There is no `sign` method on `SibnaIdentity` and no `SibnaIdentity.destroy`. The native `sibna_identity_destroy` symbol is declared in `_SibnaBindings` but is not called from Dart — once the corresponding `SibnaIdentity` is generated via `SibnaContext.generateIdentity()` (when that wrapper is added), the identity handle will need to be tracked and destroyed.

> **Note**: there is currently **no** `SibnaContext.generateIdentity()` method in this plugin's Dart wrapper. The FFI symbol `sibna_identity_generate` is declared in `_SibnaBindings`, but the public Dart surface for generating an identity has not been added. Use the native core directly or wait for the wrapper.

### `class SibnaSafetyNumber`

Identical to the Dart SDK. SHA-512 based, deterministic, 16 decimal groups of 5 digits. `matches()` is constant-time over the 32-byte fingerprint.

### Error model

`SibnaErrorCode` matches the FFI codes (0…13, 100, 101) — see the Dart SDK README for the full table. `SibnaError`, `SibnaNotInitializedError`, `SibnaPluginError`, and `SibnaValidationError` are the exception types.

## Security notes

- The password passed to `SibnaContext.create()` is zeroed in native memory immediately after the FFI call. Dart-side copies are not auto-zeroed — `secureClear` them yourself.
- All input buffers that are copied into native memory (`keyPtr`, `ctPtr`, `adPtr`) are zeroed before being freed in the `finally` block of `SibnaCrypto.encrypt` and `SibnaCrypto.decrypt`.
- `SibnaCrypto` rejects all-zero 32-byte keys and messages outside `[1, 10 MiB]`.
- `SibnaSafetyNumber.matches` is constant-time over the 32-byte fingerprint.
- Native randomness comes from `sibna_random_bytes`, which the Rust core fills from the OS CSPRNG.

## Limitations

- `SibnaContext` exposes only `create`, `createSession`, and `dispose`. Identity generation, device linking, group creation, statistics, and message routing are not exposed in this plugin's Dart surface.
- `SibnaIdentity` is a value type — it has no `sign` method and no way to free a native handle from Dart.
- `SibnaGroup` is a thin wrapper around `sibna_group_create` / `sibna_group_destroy`. The encrypt/decrypt/member management methods that the Dart SDK exposes are not present here.
- The package is not currently published to pub.dev.

## License

Apache-2.0 OR MIT
