part of '../sibna_flutter.dart';

class SibnaIdentity {
  /// Ed25519 public key (32 bytes)
  final Uint8List ed25519Public;
  /// X25519 public key (32 bytes)
  final Uint8List x25519Public;

  const SibnaIdentity({
    required this.ed25519Public,
    required this.x25519Public,
  });

  /// Get a hex fingerprint for display / logging (non-secret).
  String get fingerprint {
    final digest = sha256.convert([...ed25519Public, ...x25519Public]);
    return digest.toString().substring(0, 16);
  }

  /// Validate that public keys are well-formed (non-zero, correct length).
  bool get isValid =>
      ed25519Public.length == 32 &&
      x25519Public.length == 32 &&
      !ed25519Public.every((b) => b == 0) &&
      !x25519Public.every((b) => b == 0);

  @override
  String toString() => 'SibnaIdentity(fingerprint: $fingerprint)';
}
