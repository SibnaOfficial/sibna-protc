part of '../sibna_protocol.dart';

/// Identity key pair for authentication
class IdentityKeyPair {
  /// Ed25519 public key (32 bytes)
  final Uint8List ed25519PublicKey;

  /// X25519 public key (32 bytes)
  final Uint8List x25519PublicKey;

  /// Key fingerprint
  final String fingerprint;

  /// Creation timestamp
  final DateTime createdAt;

  /// Private constructor
  IdentityKeyPair._({
    required this.ed25519PublicKey,
    required this.x25519PublicKey,
    required this.fingerprint,
    required this.createdAt,
  });

  /// Create from public keys (private keys are managed by native library)
  factory IdentityKeyPair.fromPublicKeys(
    Uint8List ed25519Public,
    Uint8List x25519Public,
  ) {
    // Calculate fingerprint
    final combined = Uint8List(ed25519Public.length + x25519Public.length);
    combined.setRange(0, ed25519Public.length, ed25519Public);
    combined.setRange(ed25519Public.length, combined.length, x25519Public);

    final hash = sha256.convert(combined);
    final fingerprint = hex.encode(hash.bytes).substring(0, 16);

    return IdentityKeyPair._(
      ed25519PublicKey: Uint8List.fromList(ed25519Public),
      x25519PublicKey: Uint8List.fromList(x25519Public),
      fingerprint: fingerprint,
      createdAt: DateTime.now(),
    );
  }

  /// Get the public key as a hex string
  String get publicKeyHex => x25519PublicKey.toHex();

  /// Get the public key as a base64 string
  String get publicKeyBase64 => x25519PublicKey.toBase64();

  /// Verify a signature
  bool verifySignature(Uint8List data, Uint8List signature) {
    // This would call the native library in production
    // For now, return a placeholder
    return signature.length == 64;
  }

  /// Sign data
  Uint8List sign(Uint8List data) {
    // This would call the native library in production
    throw UnimplementedError('Signing requires native library');
  }

  @override
  String toString() => 'IdentityKeyPair(fingerprint: $fingerprint)';

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is IdentityKeyPair &&
      SibnaUtils.constantTimeEquals(ed25519PublicKey, other.ed25519PublicKey) &&
      SibnaUtils.constantTimeEquals(x25519PublicKey, other.x25519PublicKey);
  }

  @override
  int get hashCode => Object.hash(
    ed25519PublicKey.toHex(),
    x25519PublicKey.toHex(),
  );
}

/// Prekey bundle for X3DH handshake
class PreKeyBundle {
  /// Identity key (Ed25519 public key)
  final Uint8List identityKey;

  /// Signed prekey (X25519 public key)
  final Uint8List signedPrekey;

  /// Signature of signed prekey
  final Uint8List signature;

  /// One-time prekey (optional, X25519 public key)
  final Uint8List? oneTimePrekey;

  /// Bundle timestamp
  final DateTime timestamp;

  /// Create a new prekey bundle
  PreKeyBundle({
    required this.identityKey,
    required this.signedPrekey,
    required this.signature,
    this.oneTimePrekey,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  /// Serialize to bytes
  Uint8List toBytes() {
    final hasOneTime = oneTimePrekey != null ? 1 : 0;
    final oneTimeLen = oneTimePrekey?.length ?? 0;

    final result = BytesBuilder()
      ..add(identityKey)
      ..add(signedPrekey)
      ..add(signature)
      ..addByte(hasOneTime);

    if (oneTimePrekey != null) {
      result.add(oneTimePrekey!);
    }

    // Add timestamp
    final timestampBytes = ByteData(8)
      ..setUint64(0, timestamp.millisecondsSinceEpoch ~/ 1000, Endian.little);
    result.add(timestampBytes.buffer.asUint8List());

    return result.toBytes();
  }

  /// Deserialize from bytes
  factory PreKeyBundle.fromBytes(Uint8List bytes) {
    var offset = 0;

    final identityKey = bytes.sublist(offset, offset + 32);
    offset += 32;

    final signedPrekey = bytes.sublist(offset, offset + 32);
    offset += 32;

    final signature = bytes.sublist(offset, offset + 64);
    offset += 64;

    final hasOneTime = bytes[offset];
    offset += 1;

    Uint8List? oneTimePrekey;
    if (hasOneTime == 1) {
      oneTimePrekey = bytes.sublist(offset, offset + 32);
      offset += 32;
    }

    final timestampBytes = bytes.sublist(offset, offset + 8);
    final timestampData = ByteData.sublistView(Uint8List.fromList(timestampBytes));
    final timestamp = DateTime.fromMillisecondsSinceEpoch(
      timestampData.getUint64(0, Endian.little) * 1000,
    );

    return PreKeyBundle(
      identityKey: identityKey,
      signedPrekey: signedPrekey,
      signature: signature,
      oneTimePrekey: oneTimePrekey,
      timestamp: timestamp,
    );
  }

  /// Check if the bundle has expired (older than 7 days)
  bool get isExpired {
    final now = DateTime.now();
    return now.difference(timestamp).inDays > 7;
  }

  /// Verify the signature
  bool verifySignature(Uint8List identityPublicKey) {
    // This would call the native library in production
    // For now, return a placeholder
    return signature.length == 64;
  }

  @override
  String toString() => 'PreKeyBundle(expired: $isExpired)';
}
