# sibna_flutter

Flutter plugin for the Sibna Protocol. It provides bindings to the core Rust library, exposing X3DH and Double Ratchet functionality to Dart.

## Platform support

- Android: arm64, armv7, x86_64
- iOS: arm64, x86_64
- Windows: x86_64
- Linux: x86_64
- macOS: arm64, x86_64

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  sibna_flutter: ^1.0.4
```

## Usage

```dart
import 'package:sibna_flutter/sibna_flutter.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await SibnaFlutter.initialize();

  final key = SibnaCrypto.generateKey();
  final ciphertext = SibnaCrypto.encrypt(key, "data", associatedData: "header");
  final plaintext = SibnaCrypto.decrypt(key, ciphertext, associatedData: "header");
}
```

## Notes

- Keys are cleared from memory via zeroize limits in native code
- Cryptographic execution delegates to background isolates using `compute()`
