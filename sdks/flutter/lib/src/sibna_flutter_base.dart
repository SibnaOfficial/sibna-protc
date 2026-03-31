part of '../sibna_flutter.dart';

const String sibnaVersion = '1.0.0';
const int protocolVersion = 9;
const int keyLength       = 32;
const int nonceLength     = 12;
const int tagLength       = 16;
const int maxMessageSize  = 10 * 1024 * 1024;

/// Main plugin class — initialize before use
class SibnaFlutter {
  static DynamicLibrary? _lib;
  static _SibnaBindings? _bindings;
  static bool _initialized = false;

  static bool get isInitialized => _initialized;

  /// Initialize the plugin. Call once in `main()` before `runApp()`.
  ///
  /// ```dart
  /// void main() async {
  ///   WidgetsFlutterBinding.ensureInitialized();
  ///   await SibnaFlutter.initialize();
  ///   runApp(MyApp());
  /// }
  /// ```
  static Future<void> initialize({String? libraryPath}) async {
    if (_initialized) return;

    try {
      _lib = libraryPath != null
          ? DynamicLibrary.open(libraryPath)
          : await _resolveLibrary();
      _bindings = _SibnaBindings(_lib!);
      _initialized = true;
    } catch (e) {
      throw SibnaPluginError(
        'Failed to initialize Sibna native library: $e\n'
        'Make sure the native library is included in your build.',
      );
    }
  }

  /// Resolve library path based on platform
  static Future<DynamicLibrary> _resolveLibrary() async {
    if (Platform.isAndroid) {
      // Android: library is bundled via gradle (ffiPlugin: true)
      return DynamicLibrary.open('libsibna.so');
    }

    if (Platform.isIOS) {
      // iOS: statically linked via Xcode (ffiPlugin: true)
      return DynamicLibrary.process();
    }

    if (Platform.isWindows) {
      // Windows: sibna.dll next to executable
      final exeDir = path.dirname(Platform.resolvedExecutable);
      final candidates = [
        path.join(exeDir, 'sibna.dll'),
        path.join(exeDir, 'data', 'flutter_assets', 'sibna.dll'),
      ];
      for (final p in candidates) {
        if (File(p).existsSync()) return DynamicLibrary.open(p);
      }
      // Fallback: try system PATH
      return DynamicLibrary.open('sibna.dll');
    }

    if (Platform.isMacOS) {
      final appDir = await getApplicationSupportDirectory();
      final candidates = [
        path.join(path.dirname(Platform.resolvedExecutable),
            '..', 'Frameworks', 'libsibna.dylib'),
        path.join(appDir.path, 'libsibna.dylib'),
      ];
      for (final p in candidates) {
        if (File(p).existsSync()) return DynamicLibrary.open(p);
      }
      return DynamicLibrary.open('libsibna.dylib');
    }

    if (Platform.isLinux) {
      final exeDir = path.dirname(Platform.resolvedExecutable);
      final candidates = [
        path.join(exeDir, 'lib', 'libsibna.so'),
        path.join(exeDir, 'libsibna.so'),
      ];
      for (final p in candidates) {
        if (File(p).existsSync()) return DynamicLibrary.open(p);
      }
      return DynamicLibrary.open('libsibna.so');
    }

    throw UnsupportedError(
      'Platform not supported: ${Platform.operatingSystem}',
    );
  }

  /// Get internal bindings (package-private)
  static _SibnaBindings get bindings {
    if (!_initialized || _bindings == null) {
      throw const SibnaNotInitializedError();
    }
    return _bindings!;
  }

  /// Protocol version from native library
  static String get nativeVersion {
    if (!_initialized) return sibnaVersion;
    final buf = calloc<Char>(32);
    try {
      bindings.sibna_version(buf, 32);
      return buf.cast<Utf8>().toDartString();
    } finally {
      calloc.free(buf);
    }
  }

  /// Dispose native resources (call on app exit)
  static void dispose() {
    _lib = null;
    _bindings = null;
    _initialized = false;
  }
}

// ─────────────────────────────────────────────────────────────
// Internal helper: copy Dart bytes → native memory
// ─────────────────────────────────────────────────────────────
Pointer<Uint8> _copyToNative(Uint8List data) {
  final ptr = calloc<Uint8>(data.length);
  ptr.asTypedList(data.length).setAll(0, data);
  return ptr;
}

// ─────────────────────────────────────────────────────────────
// Internal helper: read ByteBuffer from native and free it
// ─────────────────────────────────────────────────────────────
Uint8List _readAndFreeBuffer(Pointer<_ByteBuffer> buf) {
  final result = Uint8List.fromList(
    buf.ref.data.asTypedList(buf.ref.len),
  );
  SibnaFlutter.bindings.sibna_free_buffer(buf);
  return result;
}

// ─────────────────────────────────────────────────────────────
// Internal helper: check FFI result code
// ─────────────────────────────────────────────────────────────
void _checkResult(int code, {required String op}) {
  if (code == 0) return;
  final err = SibnaErrorCode.fromCode(code);
  throw SibnaError(err, 'Operation "$op" failed: ${err.message}');
}
