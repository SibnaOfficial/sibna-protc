/// Sibna Protocol v3.0.1 — Standalone Cryptographic Primitives
///
/// Provides Ed25519, X25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256,
/// SHA-256, SHA-512, Blake3, and secure random bytes.
///
/// All protocol constants match the Rust core exactly.
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as hash_pkg;

// ── Constants ────────────────────────────────────────────────────────────────

const int keyLength = 32;
const int nonceLength = 12;
const int tagLength = 16;
const int minCompatibleVersion = 9;

// ── Secure Random ────────────────────────────────────────────────────────────

/// Cryptographically secure random bytes.
Uint8List randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(
    List.generate(length, (_) => random.nextInt(256)),
  );
}

// ── Low-Order X25519 Points ─────────────────────────────────────────────────

/// The 8 known low-order X25519 public keys that must be rejected.
final Set<Uint8List> lowOrderPoints = {
  Uint8List.fromList([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]),
  Uint8List.fromList([
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]),
  Uint8List.fromList([
    0xe0, 0xeb, 0x8a, 0x31, 0x14, 0x50, 0x9d, 0xe3,
    0x50, 0x04, 0x59, 0x45, 0x0f, 0x1f, 0x56, 0xe3,
    0x9c, 0xc0, 0x38, 0x14, 0xc1, 0x3e, 0xfc, 0x4b,
    0x3f, 0xb0, 0x83, 0x9e, 0x41, 0xf8, 0x0f, 0x17,
  ]),
  Uint8List.fromList([
    0xc3, 0xad, 0xa2, 0x83, 0x04, 0xf5, 0x36, 0x65,
    0x96, 0x6e, 0x72, 0xca, 0x07, 0xde, 0x56, 0x14,
    0xa4, 0xc0, 0x0c, 0xeb, 0x53, 0x4f, 0xbb, 0x99,
    0x76, 0x74, 0x01, 0xc0, 0x29, 0x5c, 0x59, 0x0f,
  ]),
  Uint8List.fromList([
    0x50, 0x4c, 0x00, 0xc7, 0xff, 0x66, 0x16, 0x83,
    0x0c, 0xa1, 0xda, 0x12, 0x0b, 0x0b, 0xba, 0x22,
    0xa2, 0xf4, 0x41, 0x57, 0x29, 0x8b, 0x3c, 0xd5,
    0x79, 0xe9, 0x51, 0x38, 0xd9, 0x6f, 0x8c, 0x17,
  ]),
  Uint8List.fromList([
    0xd8, 0x52, 0x7d, 0x1f, 0x00, 0x6f, 0x51, 0xe8,
    0xb6, 0x54, 0x2d, 0x6a, 0xe2, 0x7e, 0x09, 0xeb,
    0x88, 0xae, 0xc0, 0xc7, 0x1e, 0x9c, 0x75, 0xcf,
    0xd2, 0xc1, 0x7d, 0x4d, 0x2b, 0x13, 0xd0, 0x0e,
  ]),
  Uint8List.fromList([
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7e,
  ]),
  Uint8List.fromList([
    0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ]),
};

bool _isLowOrderPoint(List<int> publicKey) {
  if (publicKey.length != 32) return false;
  for (final point in lowOrderPoints) {
    if (_bytesEqual(publicKey, point)) return true;
  }
  return false;
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// ── Ed25519 Key Pair ────────────────────────────────────────────────────────

/// Ed25519 keypair for signing and identity.
class Ed25519KeyPair {
  final SimplePublicKey _publicKey;
  final SimpleKeyPair _keyPair;

  Ed25519KeyPair._(this._keyPair, this._publicKey);

  /// Generate a new random Ed25519 key pair.
  static Future<Ed25519KeyPair> generate() async {
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPair();
    final publicKey = await keyPair.extractPublicKey();
    return Ed25519KeyPair._(keyPair, publicKey);
  }

  /// Create from a 32-byte seed.
  static Future<Ed25519KeyPair> fromSeed(Uint8List seed) async {
    if (seed.length != 32) throw ArgumentError('Seed must be 32 bytes');
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPairFromSeed(seed);
    final publicKey = await keyPair.extractPublicKey();
    return Ed25519KeyPair._(keyPair, publicKey);
  }

  /// The 32-byte Ed25519 public key.
  Uint8List get publicKey => Uint8List.fromList(_publicKey.bytes);

  /// The raw 32-byte Ed25519 private key seed.
  Future<Uint8List> get privateKey async {
    final extracted = await _keyPair.extract();
    return Uint8List.fromList(extracted.bytes);
  }

  /// Sign [data] and return the 64-byte Ed25519 signature.
  Future<Uint8List> sign(Uint8List data) async {
    final algorithm = Ed25519();
    final signature = await algorithm.sign(data, keyPair: _keyPair);
    return Uint8List.fromList(signature.bytes);
  }

  /// Verify [signature] over [data] using this key pair's public key.
  Future<bool> verify(Uint8List data, Uint8List signature) async {
    final algorithm = Ed25519();
    final sig = Signature(signature, publicKey: _publicKey);
    return await algorithm.verify(data, signature: sig);
  }

  /// Verify a signature against a given public key bytes (static).
  static Future<bool> verifyWithKey(
    Uint8List publicKeyBytes,
    Uint8List data,
    Uint8List signature,
  ) async {
    final algorithm = Ed25519();
    final pk = SimplePublicKey(publicKeyBytes, type: KeyPairType.ed25519);
    final sig = Signature(signature, publicKey: pk);
    return await algorithm.verify(data, signature: sig);
  }
}

// ── X25519 Key Pair ─────────────────────────────────────────────────────────

/// X25519 keypair for Diffie-Hellman key exchange.
class X25519KeyPair {
  final SimpleKeyPair _keyPair;
  final SimplePublicKey _publicKey;

  X25519KeyPair._(this._keyPair, this._publicKey);

  /// Generate a new random X25519 key pair.
  static Future<X25519KeyPair> generate() async {
    final algorithm = X25519();
    final keyPair = await algorithm.newKeyPair();
    final publicKey = await keyPair.extractPublicKey();
    return X25519KeyPair._(keyPair, publicKey);
  }

  /// Create from a 32-byte seed.
  static Future<X25519KeyPair> fromSeed(Uint8List seed) async {
    if (seed.length != 32) throw ArgumentError('Seed must be 32 bytes');
    final algorithm = X25519();
    final keyPair = await algorithm.newKeyPairFromSeed(seed);
    final publicKey = await keyPair.extractPublicKey();
    return X25519KeyPair._(keyPair, publicKey);
  }

  /// Create from raw 32-byte private key bytes.
  static Future<X25519KeyPair> fromPrivateBytes(Uint8List privateBytes) async {
    if (privateBytes.length != 32) {
      throw ArgumentError('Private key must be 32 bytes');
    }
    final algorithm = X25519();
    final keyPair = await algorithm.newKeyPairFromSeed(privateBytes);
    final publicKey = await keyPair.extractPublicKey();
    return X25519KeyPair._(keyPair, publicKey);
  }

  /// The 32-byte X25519 public key.
  Uint8List get publicKey => Uint8List.fromList(_publicKey.bytes);

  /// The raw 32-byte X25519 private key.
  Future<Uint8List> get privateKey async {
    final extracted = await _keyPair.extract();
    return Uint8List.fromList(extracted.bytes);
  }

  /// Perform X25519 DH and return 32-byte shared secret.
  /// Rejects low-order points.
  Future<Uint8List> dh(Uint8List remotePublicKey) async {
    if (remotePublicKey.length != 32) {
      throw ArgumentError('Remote public key must be 32 bytes');
    }
    if (_isLowOrderPoint(remotePublicKey)) {
      throw ArgumentError('Rejecting low-order X25519 public key');
    }
    final algorithm = X25519();
    final remoteKey =
        SimplePublicKey(remotePublicKey, type: KeyPairType.x25519);
    final sharedSecret = await algorithm.sharedSecretKey(
      keyPair: _keyPair,
      remotePublicKey: remoteKey,
    );
    final secretBytes = await sharedSecret.extract();
    return Uint8List.fromList(secretBytes.bytes);
  }
}

// ── HKDF-SHA256 ─────────────────────────────────────────────────────────────

/// HKDF-Extract with SHA-256.
Uint8List hkdfExtract(Uint8List salt, Uint8List ikm) {
  final hmac = hash_pkg.Hmac(hash_pkg.sha256, salt);
  return Uint8List.fromList(hmac.convert(ikm).bytes);
}

/// HKDF-Expand with SHA-256.
Uint8List hkdfExpand(Uint8List prk, Uint8List info, {int length = 32}) {
  final n = (length + 31) ~/ 32;
  final okm = <int>[];
  var prev = <int>[];

  for (int i = 1; i <= n; i++) {
    final hmac = hash_pkg.Hmac(hash_pkg.sha256, prk);
    final data = <int>[...prev, ...info, i];
    final result = hmac.convert(data);
    okm.addAll(result.bytes);
    prev = result.bytes;
  }

  return Uint8List.fromList(okm.sublist(0, length));
}

/// Full HKDF-SHA256: Extract-then-Expand.
Uint8List hkdf(
  Uint8List ikm, {
  Uint8List? salt,
  Uint8List? info,
  int length = 32,
}) {
  final prk = hkdfExtract(
    salt ?? Uint8List(keyLength),
    ikm,
  );
  return hkdfExpand(prk, info ?? Uint8List(0), length: length);
}

// ── HMAC-SHA256 ─────────────────────────────────────────────────────────────

/// HMAC-SHA256.
Uint8List hmacSha256(Uint8List key, Uint8List data) {
  final hmac = hash_pkg.Hmac(hash_pkg.sha256, key);
  return Uint8List.fromList(hmac.convert(data).bytes);
}

// ── SHA-256 / SHA-512 ───────────────────────────────────────────────────────

/// SHA-256 hash.
Uint8List sha256Hash(Uint8List data) {
  return Uint8List.fromList(hash_pkg.sha256.convert(data).bytes);
}

/// SHA-512 hash.
Uint8List sha512Hash(Uint8List data) {
  return Uint8List.fromList(hash_pkg.sha512.convert(data).bytes);
}

// ── Blake3 (X3DH transcript hashing) ────────────────────────────────────────

/// Blake3 hash of multiple parts.
///
/// The Dart `cryptography` package does not ship a Blake3 implementation.
/// This uses SHA-256 as a fallback, matching the Python fallback behavior.
/// For production cross-platform compatibility with Rust/Python, integrate
/// a native Blake3 binding or use the `blake3` Dart package when available.
Future<Uint8List> blake3Hash(List<Uint8List> parts) async {
  final digest = hash_pkg.sha256;
  final output = <int>[];
  for (final part in parts) {
    output.addAll(part);
  }
  return Uint8List.fromList(digest.convert(output).bytes);
}

// ── ChaCha20-Poly1305 ──────────────────────────────────────────────────────

/// Encrypt with ChaCha20-Poly1305.
///
/// Returns nonce(12) || ciphertext || tag(16).
/// If [nonce] is not provided, a random 12-byte nonce is generated.
/// [nonce] must be exactly 12 bytes if provided.
Future<Uint8List> chacha20Poly1305Encrypt(
  Uint8List key,
  Uint8List plaintext, {
  Uint8List? associatedData,
  Uint8List? nonce,
}) async {
  if (key.length != keyLength) {
    throw ArgumentError('Key must be $keyLength bytes');
  }

  final algorithm = Chacha20.poly1305Aead();
  final secretKey = SecretKey(key);
  final aad = associatedData ?? Uint8List(0);

  final secretBox = await algorithm.encrypt(
    plaintext,
    secretKey: secretKey,
    nonce: nonce,
    aad: aad,
  );

  return Uint8List.fromList([
    ...secretBox.nonce,
    ...secretBox.cipherText,
    ...secretBox.mac.bytes,
  ]);
}

/// Decrypt data encrypted with [chacha20Poly1305Encrypt].
///
/// Input format: nonce(12) || ciphertext || tag(16).
/// If [nonce] is provided, [data] is treated as ciphertext || tag only.
Future<Uint8List> chacha20Poly1305Decrypt(
  Uint8List key,
  Uint8List data, {
  Uint8List? associatedData,
  Uint8List? nonce,
}) async {
  if (key.length != keyLength) {
    throw ArgumentError('Key must be $keyLength bytes');
  }

  final algorithm = Chacha20.poly1305Aead();
  final secretKey = SecretKey(key);
  final aad = associatedData ?? Uint8List(0);

  Uint8List actualNonce;
  Uint8List ciphertextWithTag;

  if (nonce != null) {
    actualNonce = nonce;
    ciphertextWithTag = data;
  } else {
    if (data.length < nonceLength + tagLength) {
      throw ArgumentError('Ciphertext too short');
    }
    actualNonce = Uint8List.fromList(data.sublist(0, nonceLength));
    ciphertextWithTag = Uint8List.fromList(data.sublist(nonceLength));
  }

  if (ciphertextWithTag.length < tagLength) {
    throw ArgumentError('Ciphertext too short');
  }

  final cipherText =
      Uint8List.fromList(ciphertextWithTag.sublist(0, ciphertextWithTag.length - tagLength));
  final macBytes =
      Uint8List.fromList(ciphertextWithTag.sublist(ciphertextWithTag.length - tagLength));

  final secretBox = SecretBox(
    cipherText,
    nonce: actualNonce,
    mac: Mac(macBytes),
  );

  final result = await algorithm.decrypt(
    secretBox,
    secretKey: secretKey,
    aad: aad,
  );
  return Uint8List.fromList(result);
}

// ── Identity Key Derivation ────────────────────────────────────────────────

/// Derive Ed25519 + X25519 identity keypair from a master seed.
///
/// Matches Rust core: HKDF(seed, salt=None, info="SibnaIdentityKey_*_v1").
/// Returns (ed25519Kp, x25519Kp).
Future<(Ed25519KeyPair, X25519KeyPair)> deriveIdentityKeys(
  Uint8List masterSeed,
) async {
  final edSeed = hkdf(
    masterSeed,
    info: Uint8List.fromList([
      ...utf8.encode('SibnaIdentityKey_Ed25519_v1'),
    ]),
    length: 32,
  );
  final xSeed = hkdf(
    masterSeed,
    info: Uint8List.fromList([
      ...utf8.encode('SibnaIdentityKey_X25519_v1'),
    ]),
    length: 32,
  );
  final edKp = await Ed25519KeyPair.fromSeed(edSeed);
  final xKp = await X25519KeyPair.fromSeed(xSeed);
  return (edKp, xKp);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Constant-time byte array comparison.
bool constantTimeEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  int result = 0;
  for (int i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}

/// Convert bytes to hex string.
String bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Convert hex string to bytes.
Uint8List hexToBytes(String hex) {
  final result = <int>[];
  for (int i = 0; i < hex.length; i += 2) {
    result.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(result);
}
