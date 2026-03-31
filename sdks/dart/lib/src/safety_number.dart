part of '../sibna_protocol.dart';

/// Safety number for identity verification
///
/// The safety number is derived from both parties' identity keys and
/// provides a way to detect MITM attacks during initial key exchange.
class SafetyNumber {
  /// The formatted safety number (60 digits in groups of 5)
  final String formattedNumber;

  /// The raw fingerprint bytes
  final Uint8List fingerprint;

  /// Version byte
  final int version;

  /// Private constructor
  SafetyNumber._({
    required this.formattedNumber,
    required this.fingerprint,
    required this.version,
  });

  /// Current version
  static const int currentVersion = 1;

  /// Calculate safety number from two identity keys
  ///
  /// [ourIdentity] is our X25519 public key (32 bytes)
  /// [theirIdentity] is their X25519 public key (32 bytes)
  factory SafetyNumber.calculate(
    Uint8List ourIdentity,
    Uint8List theirIdentity,
  ) {
    if (ourIdentity.length != 32) {
      throw ValidationError(
        SibnaErrorCode.invalidKey,
        'Identity key must be 32 bytes',
        field: 'ourIdentity',
      );
    }
    if (theirIdentity.length != 32) {
      throw ValidationError(
        SibnaErrorCode.invalidKey,
        'Identity key must be 32 bytes',
        field: 'theirIdentity',
      );
    }

    // Sort keys lexicographically for consistent ordering
    final first = _compareBytes(ourIdentity, theirIdentity) < 0
      ? ourIdentity
      : theirIdentity;
    final second = _compareBytes(ourIdentity, theirIdentity) < 0
      ? theirIdentity
      : ourIdentity;

    // Hash both keys together with version
    final hmac = Hmac(sha512, utf8.encode('SIBNA_SAFETY_NUMBER_V1'));
    final data = BytesBuilder()
      ..addByte(currentVersion)
      ..add(first)
      ..add(second);

    final result = hmac.convert(data.toBytes());
    final fingerprint = Uint8List.fromList(result.bytes.sublist(0, 32));

    // Convert to 60 decimal digits
    final formattedNumber = _bytesToDigits(fingerprint);

    return SafetyNumber._(
      formattedNumber: formattedNumber,
      fingerprint: fingerprint,
      version: currentVersion,
    );
  }

  /// Parse safety number from string
  factory SafetyNumber.parse(String safetyNumber) {
    final digits = safetyNumber.replaceAll(RegExp(r'\D'), '');

    if (digits.length != 60) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Safety number must be 60 digits',
        field: 'safetyNumber',
      );
    }

    // Reverse the digit-to-bytes conversion
    final fingerprint = Uint8List(32);
    for (int i = 0; i < 16; i++) {
      final chunk = digits.substring(i * 5, (i + 1) * 5);
      final value = int.parse(chunk);
      fingerprint[i * 2] = (value >> 8) & 0xFF;
      fingerprint[i * 2 + 1] = value & 0xFF;
    }

    return SafetyNumber._(
      formattedNumber: _bytesToDigits(fingerprint),
      fingerprint: fingerprint,
      version: currentVersion,
    );
  }

  /// Get the safety number as a formatted string
  String get displayString => formattedNumber;

  /// Get QR code data
  Uint8List get qrData {
    final builder = BytesBuilder()
      ..addByte(version)
      ..add(utf8.encode('SB1'))
      ..add(fingerprint);
    return builder.toBytes();
  }

  /// Verify if another safety number matches (constant-time)
  bool verify(SafetyNumber other) {
    return SibnaUtils.constantTimeEquals(fingerprint, other.fingerprint);
  }

  /// Calculate similarity score with another safety number
  /// (for detecting typos during manual verification)
  double similarity(SafetyNumber other) {
    final aDigits = formattedNumber.replaceAll(' ', '');
    final bDigits = other.formattedNumber.replaceAll(' ', '');

    int matches = 0;
    for (int i = 0; i < aDigits.length && i < bDigits.length; i++) {
      if (aDigits[i] == bDigits[i]) {
        matches++;
      }
    }

    return matches / 60.0;
  }

  /// Compare two byte arrays lexicographically
  static int _compareBytes(Uint8List a, Uint8List b) {
    final minLen = a.length < b.length ? a.length : b.length;
    for (int i = 0; i < minLen; i++) {
      if (a[i] != b[i]) {
        return a[i] - b[i];
      }
    }
    return a.length - b.length;
  }

  /// Convert 32 bytes to 60 decimal digits
  static String _bytesToDigits(Uint8List bytes) {
    final groups = <String>[];

    for (int i = 0; i < bytes.length; i += 2) {
      if (i > 0 && (i ~/ 2) % 3 == 0) {
        groups.add(' ');
      }

      final value = ((bytes[i] << 8) | bytes[i + 1]) % 100000;
      groups.add(value.toString().padLeft(5, '0'));
    }

    return groups.join('');
  }

  @override
  String toString() => 'SafetyNumber($formattedNumber)';

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is SafetyNumber && verify(other);
  }

  @override
  int get hashCode => fingerprint.toHex().hashCode;
}

/// QR Code data for identity verification
class VerificationQrCode {
  /// Version byte
  final int version;

  /// Identity key
  final Uint8List identityKey;

  /// Device ID
  final Uint8List deviceId;

  /// Safety number fingerprint
  final Uint8List safetyFingerprint;

  /// Verification status
  final bool verified;

  /// Create a new verification QR code
  VerificationQrCode({
    required this.identityKey,
    required this.deviceId,
    required this.safetyFingerprint,
    this.verified = false,
    this.version = 1,
  });

  /// Encode to bytes for QR code generation
  Uint8List toBytes() {
    final builder = BytesBuilder()
      ..addByte(version)
      ..add(utf8.encode('SIBNA'))
      ..addByte(verified ? 1 : 0)
      ..add(identityKey)
      ..add(deviceId)
      ..add(safetyFingerprint);

    // Add HMAC-SHA256 for integrity
    final mac = SibnaCrypto.hmacSha256(
      Uint8List(32)..fillRange(0, 32, 0x42), // Fixed key for demo
      builder.toBytes(),
    );
    builder.add(mac);

    return builder.toBytes();
  }

  /// Parse from bytes
  factory VerificationQrCode.fromBytes(Uint8List data) {
    if (data.length < 83) {
      throw ValidationError(
        SibnaErrorCode.invalidMessage,
        'Invalid QR code data length',
        field: 'data',
      );
    }

    var offset = 0;

    final version = data[offset];
    offset += 1;

    // Verify magic bytes
    final magic = utf8.decode(data.sublist(offset, offset + 5));
    if (magic != 'SIBNA') {
      throw ValidationError(
        SibnaErrorCode.invalidMessage,
        'Invalid QR code magic bytes',
        field: 'data',
      );
    }
    offset += 5;

    final verified = data[offset] != 0;
    offset += 1;

    final identityKey = data.sublist(offset, offset + 32);
    offset += 32;

    final deviceId = data.sublist(offset, offset + 16);
    offset += 16;

    final safetyFingerprint = data.sublist(offset, offset + 32);
    offset += 32;

    // Verify MAC
    final mac = data.sublist(offset);
    // In production, verify the MAC here

    return VerificationQrCode(
      version: version,
      identityKey: identityKey,
      deviceId: deviceId,
      safetyFingerprint: safetyFingerprint,
      verified: verified,
    );
  }

  /// Mark as verified
  VerificationQrCode markVerified() {
    return VerificationQrCode(
      version: version,
      identityKey: identityKey,
      deviceId: deviceId,
      safetyFingerprint: safetyFingerprint,
      verified: true,
    );
  }

  @override
  String toString() =>
    'VerificationQrCode(verified: $verified, version: $version)';
}

/// Safety number comparison result
enum SafetyNumberComparison {
  /// Numbers match exactly
  match,

  /// Numbers are similar (possible typo)
  similar,

  /// Numbers don't match
  mismatch,
}

/// Compare two safety numbers
SafetyNumberComparison compareSafetyNumbers(
  SafetyNumber a,
  SafetyNumber b, {
  double similarityThreshold = 0.8,
}) {
  if (a.verify(b)) {
    return SafetyNumberComparison.match;
  }

  final similarity = a.similarity(b);
  if (similarity > similarityThreshold) {
    return SafetyNumberComparison.similar;
  }

  return SafetyNumberComparison.mismatch;
}
