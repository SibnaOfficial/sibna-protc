part of '../sibna_flutter.dart';

class SibnaSafetyNumber {
  final String digits;
  final Uint8List fingerprint;

  const SibnaSafetyNumber._({
    required this.digits,
    required this.fingerprint,
  });

  /// Calculate safety number from two 32-byte X25519 identity keys.
  ///
  /// Order of [ourKey] and [theirKey] does NOT matter — the result is
  /// always the same regardless of who calculates it first.
  factory SibnaSafetyNumber.calculate(
    Uint8List ourKey,
    Uint8List theirKey,
  ) {
    if (ourKey.length != 32 || theirKey.length != 32) {
      throw SibnaValidationError('key', 'Identity keys must be 32 bytes');
    }

    // Sort lexicographically so both sides produce identical output
    final List<int> first, second;
    bool aLessThan = true;
    for (var i = 0; i < 32; i++) {
      if (ourKey[i] < theirKey[i]) { aLessThan = true; break; }
      if (ourKey[i] > theirKey[i]) { aLessThan = false; break; }
    }
    if (aLessThan) {
      first  = ourKey;
      second = theirKey;
    } else {
      first  = theirKey;
      second = ourKey;
    }

    // SHA-512 hash with domain separation
    const version = 1;
    final input = <int>[
      version,
      ...utf8Label('SIBNA_SAFETY_NUMBER_V1'),
      ...first,
      ...second,
    ];
    final hash = sha512.convert(input);
    final fp = Uint8List.fromList(hash.bytes.sublist(0, 32));

    return SibnaSafetyNumber._(
      digits: _toDigits(fp),
      fingerprint: fp,
    );
  }

  /// UTF-8 bytes for a string label
  static List<int> utf8Label(String s) => s.codeUnits;

  /// Convert 32 bytes → 80 decimal digits (16 groups × 5 digits)
  static String _toDigits(Uint8List bytes) {
    final buf = StringBuffer();
    for (var i = 0; i < 16; i++) {
      if (i > 0 && i % 3 == 0) buf.write(' ');
      final hi = bytes[i * 2];
      final lo = bytes[i * 2 + 1];
      final val = (hi << 8) | lo;
      buf.write((val % 100000).toString().padLeft(5, '0'));
    }
    return buf.toString();
  }

  /// Compare two safety numbers in constant-time.
  bool matches(SibnaSafetyNumber other) {
    if (fingerprint.length != other.fingerprint.length) return false;
    var diff = 0;
    for (var i = 0; i < fingerprint.length; i++) {
      diff |= fingerprint[i] ^ other.fingerprint[i];
    }
    return diff == 0;
  }

  /// Formatted string for display to the user.
  String get formatted => digits;

  @override
  String toString() => 'SibnaSafetyNumber($digits)';
}
