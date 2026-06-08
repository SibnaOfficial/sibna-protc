/// Sibna Protocol v3.0.1 — Safety Numbers
///
/// 80-digit human-readable fingerprints for identity verification.
/// Matches the Rust core's SafetyNumber implementation exactly:
///   - SHA-512(0x01 || "SIBNA_SAFETY_NUMBER_V1" || first_key || second_key)
///   - First 32 bytes of hash → 80 decimal digits (16 groups of 5)
///   - QR format: version(1) + "SB1"(3) + fingerprint(32) = 36 bytes
import 'dart:convert';
import 'dart:typed_data';

import 'crypto.dart';

/// Safety number for identity verification.
///
/// The safety number is derived from both parties' identity keys and
/// provides a way to detect MITM attacks during initial key exchange.
class SafetyNumber {
  /// The 80-digit string (16 groups of 5 digits, no separators).
  final String digits;

  /// The raw 32-byte fingerprint.
  final Uint8List fingerprint;

  /// Version byte.
  final int version;

  /// Current version.
  static const int currentVersion = 1;

  SafetyNumber._({
    required this.digits,
    required this.fingerprint,
    this.version = currentVersion,
  });

  /// Calculate safety number from two X25519 public keys.
  ///
  /// Keys are sorted lexicographically for consistent ordering.
  factory SafetyNumber.calculate(
    Uint8List ourIdentity,
    Uint8List theirIdentity,
  ) {
    if (ourIdentity.length != 32) {
      throw ArgumentError('Identity key must be 32 bytes');
    }
    if (theirIdentity.length != 32) {
      throw ArgumentError('Identity key must be 32 bytes');
    }

    final first = constantTimeEquals(ourIdentity, theirIdentity)
        ? ourIdentity
        : (_bytesLessThan(ourIdentity, theirIdentity)
            ? ourIdentity
            : theirIdentity);
    final second = constantTimeEquals(ourIdentity, theirIdentity)
        ? theirIdentity
        : (_bytesLessThan(ourIdentity, theirIdentity)
            ? theirIdentity
            : ourIdentity);

    final data = Uint8List.fromList([
      currentVersion,
      ...utf8.encode('SIBNA_SAFETY_NUMBER_V1'),
      ...first,
      ...second,
    ]);

    final hash = sha512Hash(data);
    final fp = Uint8List.fromList(hash.sublist(0, 32));
    final d = _bytesToDigits(fp);

    return SafetyNumber._(
      digits: d,
      fingerprint: fp,
    );
  }

  /// Calculate safety number with additional data (e.g. for group verification).
  factory SafetyNumber.calculateWithExtra(
    Uint8List ourIdentity,
    Uint8List theirIdentity,
    Uint8List extraData,
  ) {
    if (ourIdentity.length != 32) {
      throw ArgumentError('Identity key must be 32 bytes');
    }
    if (theirIdentity.length != 32) {
      throw ArgumentError('Identity key must be 32 bytes');
    }

    final first = _bytesLessThan(ourIdentity, theirIdentity)
        ? ourIdentity
        : theirIdentity;
    final second = _bytesLessThan(ourIdentity, theirIdentity)
        ? theirIdentity
        : ourIdentity;

    final data = Uint8List.fromList([
      currentVersion,
      ...utf8.encode('SIBNA_SAFETY_NUMBER_V1_EXTRA'),
      ...first,
      ...second,
      ...extraData,
    ]);

    final hash = sha512Hash(data);
    final fp = Uint8List.fromList(hash.sublist(0, 32));
    final d = _bytesToDigits(fp);

    return SafetyNumber._(
      digits: d,
      fingerprint: fp,
    );
  }

  /// Parse safety number from its string representation.
  factory SafetyNumber.fromString(String s) {
    final digitsStr = s.replaceAll(RegExp(r'\D'), '');
    if (digitsStr.length != 80) {
      throw ArgumentError('Expected 80 digits, got ${digitsStr.length}');
    }
    final fp = _digitsToBytes(digitsStr);
    return SafetyNumber._(
      digits: digitsStr,
      fingerprint: fp,
    );
  }

  /// Return the 80-digit string (no separators).
  String asString() => digits;

  /// Return the safety number formatted for display.
  ///
  /// [groupSize]: digits per group (default 5)
  /// [groupsPerLine]: groups per line (default 8)
  String formatted({int groupSize = 5, int groupsPerLine = 8}) {
    final groups = <String>[];
    for (int i = 0; i < digits.length; i += groupSize) {
      final end = (i + groupSize < digits.length) ? i + groupSize : digits.length;
      groups.add(digits.substring(i, end));
    }

    final lines = <String>[];
    for (int i = 0; i < groups.length; i += groupsPerLine) {
      final end = (i + groupsPerLine < groups.length)
          ? i + groupsPerLine
          : groups.length;
      lines.add(groups.sublist(i, end).join(' '));
    }
    return lines.join('\n');
  }

  /// QR code data: version(1) + "SB1"(3) + fingerprint(32) = 36 bytes.
  Uint8List qrData() {
    return Uint8List.fromList([
      version,
      ...utf8.encode('SB1'),
      ...fingerprint,
    ]);
  }

  /// Constant-time comparison with another safety number.
  bool verify(SafetyNumber other) {
    return constantTimeEquals(fingerprint, other.fingerprint);
  }

  @override
  String toString() => formatted();

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! SafetyNumber) return false;
    return verify(other);
  }

  @override
  int get hashCode => fingerprint.hashCode;

  // ── Internal helpers ────────────────────────────────────────────────

  /// Convert 32 bytes to 80 decimal digits (16 chunks × 5 digits).
  static String _bytesToDigits(Uint8List data) {
    final parts = <String>[];
    for (int i = 0; i < 32; i += 2) {
      final value = (data[i] << 8) | data[i + 1];
      parts.add('${value % 100000}'.padLeft(5, '0'));
    }
    return parts.join('');
  }

  /// Convert 80 digits back to 32 bytes.
  static Uint8List _digitsToBytes(String digits) {
    final result = Uint8List(32);
    var byteIdx = 0;
    for (int i = 0; i < 80; i += 5) {
      final chunk = digits.substring(i, i + 5);
      final value = int.parse(chunk);
      result[byteIdx] = (value >> 8) & 0xFF;
      result[byteIdx + 1] = value & 0xFF;
      byteIdx += 2;
    }
    return result;
  }

  /// Lexicographic byte comparison.
  static bool _bytesLessThan(Uint8List a, Uint8List b) {
    final minLen = a.length < b.length ? a.length : b.length;
    for (int i = 0; i < minLen; i++) {
      if (a[i] < b[i]) return true;
      if (a[i] > b[i]) return false;
    }
    return a.length < b.length;
  }
}
