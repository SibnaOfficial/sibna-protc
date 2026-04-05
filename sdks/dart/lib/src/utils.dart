part of '../sibna_protocol.dart';

/// Utility functions for the Sibna SDK
class SibnaUtils {
  /// Private constructor to prevent instantiation
  SibnaUtils._();

  /// Convert a hex string to bytes
  static Uint8List hexToBytes(String hex) {
    final result = <int>[];
    for (int i = 0; i < hex.length; i += 2) {
      final byte = int.parse(hex.substring(i, i + 2), radix: 16);
      result.add(byte);
    }
    return Uint8List.fromList(result);
  }

  /// Convert bytes to a hex string
  static String bytesToHex(Uint8List bytes) {
    return hex.encode(bytes);
  }

  /// Convert bytes to a base64 string
  static String bytesToBase64(Uint8List bytes) {
    return base64Encode(bytes);
  }

  /// Convert a base64 string to bytes
  static Uint8List base64ToBytes(String base64Str) {
    return base64Decode(base64Str);
  }

  /// Securely compare two byte arrays (constant-time)
  static bool constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;

    int result = 0;
    for (int i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  /// Check if a byte array is all zeros
  static bool isAllZeros(Uint8List bytes) {
    for (final byte in bytes) {
      if (byte != 0) return false;
    }
    return true;
  }

  /// Securely clear a byte array
  static void secureClear(Uint8List bytes) {
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }

  /// Generate a random byte array
  static Uint8List randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
      List.generate(length, (_) => random.nextInt(256)),
    );
  }

  /// Validate a key length
  static void validateKeyLength(Uint8List key, {int expectedLength = keyLength}) {
    if (key.length != expectedLength) {
      throw ValidationError(
        SibnaErrorCode.invalidKey,
        'Invalid key length: expected $expectedLength, got ${key.length}',
        field: 'key',
      );
    }
  }

  /// Validate message size
  static void validateMessageSize(Uint8List message, {int maxSize = maxMessageSize}) {
    if (message.isEmpty) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Message cannot be empty',
        field: 'message',
      );
    }
    if (message.length > maxSize) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Message too large: ${message.length} > $maxSize',
        field: 'message',
      );
    }
  }

  /// Validate a timestamp
  static void validateTimestamp(int timestamp, {int maxAgeSeconds = 300}) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final age = now - timestamp;

    if (timestamp > now + 60) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Timestamp is in the future',
        field: 'timestamp',
      );
    }

    if (age > maxAgeSeconds) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Timestamp is too old: $age seconds',
        field: 'timestamp',
      );
    }
  }

  /// Format a safety number for display
  static String formatSafetyNumber(String safetyNumber) {
    final digits = safetyNumber.replaceAll(RegExp(r'\D'), '');
    final groups = <String>[];

    for (int i = 0; i < digits.length; i += 5) {
      final end = (i + 5 < digits.length) ? i + 5 : digits.length;
      groups.add(digits.substring(i, end));
    }

    return groups.join(' ');
  }

  /// Calculate fingerprint of a public key
  static String calculateFingerprint(Uint8List publicKey) {
    final hash = sha256.convert(publicKey);
    return bytesToHex(Uint8List.fromList(hash.bytes)).substring(0, 16);
  }

  /// Copy a byte array
  static Uint8List copyBytes(Uint8List bytes) {
    return Uint8List.fromList(bytes);
  }

  /// Concatenate byte arrays
  static Uint8List concatBytes(List<Uint8List> arrays) {
    final totalLength = arrays.fold<int>(0, (sum, arr) => sum + arr.length);
    final result = Uint8List(totalLength);
    var offset = 0;

    for (final arr in arrays) {
      result.setRange(offset, offset + arr.length, arr);
      offset += arr.length;
    }

    return result;
  }

  /// XOR two byte arrays
  static Uint8List xorBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      throw ArgumentError('Arrays must have the same length');
    }

    final result = Uint8List(a.length);
    for (int i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i];
    }
    return result;
  }
}

/// Extension methods for Uint8List
extension Uint8ListExtensions on Uint8List {
  /// Convert to hex string
  String toHex() => SibnaUtils.bytesToHex(this);

  /// Convert to base64 string
  String toBase64() => SibnaUtils.bytesToBase64(this);

  /// Securely clear the array
  void secureClear() => SibnaUtils.secureClear(this);

  /// Check if all zeros
  bool get isAllZeros => SibnaUtils.isAllZeros(this);

  /// Create a copy
  Uint8List copy() => SibnaUtils.copyBytes(this);

  /// Constant-time comparison
  bool constantTimeEquals(Uint8List other) =>
    SibnaUtils.constantTimeEquals(this, other);
}

/// Extension methods for String
extension StringExtensions on String {
  /// Convert hex string to bytes
  Uint8List toBytesFromHex() => SibnaUtils.hexToBytes(this);

  /// Convert base64 string to bytes
  Uint8List toBytesFromBase64() => SibnaUtils.base64ToBytes(this);
}
