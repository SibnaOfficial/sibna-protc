# sibna_flutter

Flutter plugin for the **Sibna Protocol** — a production-grade Signal Protocol E2EE implementation in Rust.

## Platform support

| Platform | Status | Native library |
|---|---|---|
| Android | ✅ | `libsibna.so` (arm64, armv7, x86_64) |
| iOS | ✅ | `libsibna.a` (static, arm64 + sim) |
| Windows | ✅ | `sibna.dll` (x86_64 MSVC) |
| Linux | ✅ | `libsibna.so` (x86_64) |
| macOS | ✅ | `libsibna.dylib` or `.a` |
| Web | ❌ | Use the WASM build of the JS SDK instead |

## Installation

```yaml
dependencies:
  sibna_flutter: ^1.0.0
```

## Setup

### 1. Build the native library

```bash
# Android (run from project root)
cargo build --release --features ffi --target aarch64-linux-android
cargo build --release --features ffi --target armv7-linux-androideabi
cargo build --release --features ffi --target x86_64-linux-android

# iOS
cargo build --release --features ffi --target aarch64-apple-ios
cargo build --release --features ffi --target aarch64-apple-ios-sim

# Windows
cargo build --release --features ffi --target x86_64-pc-windows-msvc
# Output: target/x86_64-pc-windows-msvc/release/sibna.dll

# Linux
cargo build --release --features ffi --target x86_64-unknown-linux-gnu

# macOS
cargo build --release --features ffi --target aarch64-apple-darwin
cargo build --release --features ffi --target x86_64-apple-darwin
```

### 2. Initialize the plugin

```dart
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await SibnaFlutter.initialize();
  runApp(MyApp());
}
```

## Usage

```dart
import 'package:sibna_flutter/sibna_flutter.dart';

// Generate a key
final key = SibnaCrypto.generateKey();

// Encrypt
final ct = SibnaCrypto.encrypt(key, plaintext, associatedData: aad);

// Decrypt
final pt = SibnaCrypto.decrypt(key, ct, associatedData: aad);

// Safety number (identity verification)
final sn = SibnaSafetyNumber.calculate(myPublicKey, theirPublicKey);
print(sn.formatted); // Show to user for out-of-band verification
```

## Security notes

- Keys are zeroed in native memory after use
- All operations run on a background isolate via `compute()` in production use
- The native library validates all inputs before cryptographic operations
- Use `SibnaSafetyNumber` to prevent MITM attacks during key exchange
