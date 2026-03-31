/// Sibna Protocol Dart/Flutter SDK - Ultra Secure Edition
///
/// A Dart wrapper for the Sibna secure communication protocol.
///
/// Example usage:
/// ```dart
/// import 'package:sibna_protocol/sibna_protocol.dart';
///
/// void main() async {
///   // Initialize the SDK
///   await SibnaProtocol.initialize();
///
///   // Create a secure context
///   final ctx = await SibnaContext.create(password: 'my_secure_password');
///
///   // Generate identity
///   final identity = await ctx.generateIdentity();
///
///   // Create a session
///   final session = await ctx.createSession(Uint8List.fromList([1, 2, 3]));
///
///   // Encrypt a message
///   final encrypted = await session.encrypt(
///     Uint8List.fromList(utf8.encode('Hello, World!')),
///   );
///
///   // Decrypt a message
///   final decrypted = await session.decrypt(encrypted);
///
///   print(utf8.decode(decrypted));
/// }
/// ```

library sibna_protocol;

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as path;
import 'package:crypto/crypto.dart';
import 'package:convert/convert.dart';
import 'package:synchronized/synchronized.dart';

part 'src/bindings.dart';
part 'src/context.dart';
part 'src/session.dart';
part 'src/identity.dart';
part 'src/crypto.dart';
part 'src/errors.dart';
part 'src/utils.dart';
part 'src/group.dart';
part 'src/safety_number.dart';

/// SDK Version
const String sibnaVersion = '1.0.0';

/// Protocol version number
const int protocolVersion = 9;

/// Minimum compatible version
const int minCompatibleVersion = 8;

/// Maximum message size (10 MB)
const int maxMessageSize = 10 * 1024 * 1024;

/// Key length in bytes (256 bits)
const int keyLength = 32;

/// Nonce length in bytes (96 bits)
const int nonceLength = 12;

/// Tag length in bytes (128 bits)
const int tagLength = 16;

/// Main SDK class
class SibnaProtocol {
  static DynamicLibrary? _lib;
  static final _lock = Lock();
  static bool _initialized = false;

  /// Check if the SDK is initialized
  static bool get isInitialized => _initialized;

  /// Initialize the SDK
  ///
  /// This must be called before using any other SDK functions.
  /// [libraryPath] is optional and will be auto-detected if not provided.
  static Future<void> initialize({String? libraryPath}) async {
    if (_initialized) return;

    await _lock.synchronized(() async {
      if (_initialized) return;

      if (libraryPath != null) {
        _lib = DynamicLibrary.open(libraryPath);
      } else {
        _lib = _loadLibrary();
      }

      _bindings = SibnaBindings(_lib!);
      _initialized = true;
    });
  }

  /// Get the native library
  static DynamicLibrary get lib {
    if (_lib == null) {
      throw SibnaError(
        SibnaErrorCode.notInitialized,
        'SDK not initialized. Call SibnaProtocol.initialize() first.',
      );
    }
    return _lib!;
  }

  /// Load the native library based on platform
  static DynamicLibrary _loadLibrary() {
    final String libraryName;
    
    if (Platform.isLinux) {
      libraryName = 'libsibna.so';
    } else if (Platform.isMacOS) {
      libraryName = 'libsibna.dylib';
    } else if (Platform.isWindows) {
      libraryName = 'sibna.dll';
    } else if (Platform.isAndroid) {
      libraryName = 'libsibna.so';
    } else if (Platform.isIOS) {
      libraryName = 'libsibna.dylib';
    } else {
      throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
    }

    // Try to find the library in various locations
    final searchPaths = [
      // Current directory
      path.join(Directory.current.path, libraryName),
      // Parent directory
      path.join(Directory.current.parent.path, libraryName),
      // System paths
      if (Platform.isLinux || Platform.isAndroid) '/usr/local/lib/$libraryName',
      if (Platform.isLinux || Platform.isAndroid) '/usr/lib/$libraryName',
      if (Platform.isMacOS || Platform.isIOS) '/usr/local/lib/$libraryName',
      if (Platform.isWindows) 'C:\\Windows\\System32\\$libraryName',
    ];

    for (final libPath in searchPaths) {
      if (File(libPath).existsSync()) {
        return DynamicLibrary.open(libPath);
      }
    }

    throw SibnaError(
      SibnaErrorCode.libraryNotFound,
      'Could not find $libraryName. Please provide the library path.',
    );
  }

  /// Get the protocol version
  static String get version {
    if (!_initialized) return sibnaVersion;
    
    final buffer = calloc<Char>(32);
    try {
      final result = _bindings.sibna_version(buffer, 32);
      if (result != SibnaErrorCode.ok.code) {
        return sibnaVersion;
      }
      return buffer.cast<Utf8>().toDartString();
    } finally {
      calloc.free(buffer);
    }
  }

  /// Cleanup resources
  static void cleanup() {
    _lib = null;
    _initialized = false;
  }
}

// Internal bindings instance
late final SibnaBindings _bindings;
