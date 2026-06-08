/// Sibna Protocol v3.0.1 — Group Messaging (Sender Keys)
///
/// Implements Sender Keys protocol for efficient group encryption.
/// Matches the Rust core's group module exactly:
///   - Chain key derivation: HKDF(chain_key, "SibnaGroupMessageKey_v3") = message_key
///   - Chain advance: HKDF(chain_key, "SibnaGroupChainKey_v3") = next_chain_key
///   - Wire format: group_id(32) || key_id(4) || message_number(4) || nonce(12) || ciphertext+tag
///   - Signature: Ed25519 over signable_bytes
import 'dart:convert';
import 'dart:typed_data';

import 'crypto.dart';

const int maxGroupSize = 256;
const int maxGroupMessageSize = 10 * 1024 * 1024; // 10 MB
const int defaultKeyExpirationSecs = 7 * 86400; // 7 days

// ── Sender Key ──────────────────────────────────────────────────────────────

/// Sender key for group encryption.
class SenderKey {
  Uint8List chainKey;
  int messageNumber;
  int keyId;
  DateTime createdAt;
  DateTime? expiration;

  SenderKey({
    required this.chainKey,
    this.messageNumber = 0,
    this.keyId = 0,
    DateTime? createdAt,
    this.expiration,
  }) : createdAt = createdAt ?? DateTime.now();

  /// Generate a new random sender key.
  static SenderKey generate({int keyId = 0}) {
    return SenderKey(
      chainKey: randomBytes(keyLength),
      keyId: keyId,
      expiration: DateTime.now().add(Duration(seconds: defaultKeyExpirationSecs)),
    );
  }

  /// Derive the next message key and advance the chain.
  ///
  /// Returns the message key or null if chain expired.
  Uint8List? nextMessageKey() {
    if (expiration != null && DateTime.now().isAfter(expiration!)) {
      throw StateError('Sender key expired');
    }

    // message_key = HKDF(chain_key, info="SibnaGroupMessageKey_v3")
    final messageKey = hkdf(
      chainKey,
      info: Uint8List.fromList([
        ...utf8.encode('SibnaGroupMessageKey_v3'),
      ]),
      length: keyLength,
    );

    // next_chain = HKDF(chain_key, info="SibnaGroupChainKey_v3")
    final nextChain = hkdf(
      chainKey,
      info: Uint8List.fromList([
        ...utf8.encode('SibnaGroupChainKey_v3'),
      ]),
      length: keyLength,
    );

    chainKey = nextChain;
    messageNumber++;

    return messageKey;
  }

  /// Whether this key has expired.
  bool get isExpired {
    if (expiration == null) return false;
    return DateTime.now().isAfter(expiration!);
  }

  /// Age of this key.
  Duration get age => DateTime.now().difference(createdAt);

  /// Whether this key needs rotation (expired or older than 24 hours).
  bool get needsRotation => isExpired || age.inSeconds > 86400;
}

// ── Sender Key Distribution Message ─────────────────────────────────────────

/// Key distribution message for group join.
class SenderKeyMessage {
  Uint8List groupId;
  Uint8List senderPublicKey;
  Uint8List encryptedKey;
  Uint8List signature;
  int keyId;
  DateTime timestamp;

  SenderKeyMessage({
    required this.groupId,
    required this.senderPublicKey,
    required this.encryptedKey,
    required this.signature,
    required this.keyId,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  /// Bytes to sign: group_id || key_id || encrypted_key || timestamp.
  Uint8List signableBytes() {
    final keyIdBytes = ByteData(4)..setUint32(0, keyId, Endian.little);
    final timestampBytes = ByteData(8)
      ..setInt64(0, timestamp.millisecondsSinceEpoch ~/ 1000, Endian.little);

    return Uint8List.fromList([
      ...groupId,
      ...keyIdBytes.buffer.asUint8List(),
      ...encryptedKey,
      ...timestampBytes.buffer.asUint8List(),
    ]);
  }

  /// Sign this distribution message with an Ed25519 identity.
  Future<Uint8List> sign(Ed25519KeyPair identity) async {
    signature = await identity.sign(signableBytes());
    return signature;
  }

  /// Verify the Ed25519 signature.
  Future<bool> verifySignature() async {
    if (signature.length != 64) return false;
    return await Ed25519KeyPair.verifyWithKey(
      senderPublicKey,
      signableBytes(),
      signature,
    );
  }

  /// Serialize to bytes for wire transmission.
  Uint8List toBytes() {
    final keyIdBytes = ByteData(4)..setUint32(0, keyId, Endian.little);
    final timestampBytes = ByteData(8)
      ..setInt64(0, timestamp.millisecondsSinceEpoch ~/ 1000, Endian.little);
    final encKeyLenBytes =
        ByteData(4)..setUint32(0, encryptedKey.length, Endian.little);
    final sigLenBytes =
        ByteData(4)..setUint32(0, signature.length, Endian.little);

    return Uint8List.fromList([
      ...groupId,
      ...senderPublicKey,
      ...keyIdBytes.buffer.asUint8List(),
      ...timestampBytes.buffer.asUint8List(),
      ...encKeyLenBytes.buffer.asUint8List(),
      ...encryptedKey,
      ...sigLenBytes.buffer.asUint8List(),
      ...signature,
    ]);
  }

  /// Deserialize from bytes.
  static SenderKeyMessage fromBytes(Uint8List data) {
    var offset = 0;

    final groupId = Uint8List.fromList(data.sublist(offset, offset + 32));
    offset += 32;

    final senderPublicKey =
        Uint8List.fromList(data.sublist(offset, offset + 32));
    offset += 32;

    final keyId = ByteData.sublistView(
      Uint8List.fromList(data.sublist(offset, offset + 4)),
    ).getUint32(0, Endian.little);
    offset += 4;

    final timestampSec = ByteData.sublistView(
      Uint8List.fromList(data.sublist(offset, offset + 8)),
    ).getInt64(0, Endian.little);
    offset += 8;

    final encKeyLen = ByteData.sublistView(
      Uint8List.fromList(data.sublist(offset, offset + 4)),
    ).getUint32(0, Endian.little);
    offset += 4;

    final encryptedKey =
        Uint8List.fromList(data.sublist(offset, offset + encKeyLen));
    offset += encKeyLen;

    final sigLen = ByteData.sublistView(
      Uint8List.fromList(data.sublist(offset, offset + 4)),
    ).getUint32(0, Endian.little);
    offset += 4;

    final signature =
        Uint8List.fromList(data.sublist(offset, offset + sigLen));

    return SenderKeyMessage(
      groupId: groupId,
      senderPublicKey: senderPublicKey,
      encryptedKey: encryptedKey,
      signature: signature,
      keyId: keyId,
      timestamp: DateTime.fromMillisecondsSinceEpoch(timestampSec * 1000),
    );
  }
}

// ── Group Session ───────────────────────────────────────────────────────────

/// Group encryption session using Sender Keys.
///
/// Each member has their own SenderKey. When joining, the key is
/// distributed via SenderKeyMessage encrypted to each member.
class GroupSession {
  final Uint8List groupId;
  SenderKey? _senderKey;
  final Map<Uint8List, SenderKey> _senderKeys = {};
  int _keyRotationCount = 0;

  GroupSession(this.groupId) {
    if (groupId.length != 32) {
      throw ArgumentError('group_id must be 32 bytes');
    }
  }

  /// Create a new group session with a random group ID.
  static GroupSession create({Uint8List? groupId}) {
    final gid = groupId ?? randomBytes(32);
    final session = GroupSession(gid);
    session._senderKey = SenderKey.generate(keyId: 0);
    return session;
  }

  /// The current sender key (if we are a sender).
  SenderKey? get senderKey => _senderKey;

  /// The number of known sender keys from other members.
  int get memberCount => _senderKeys.length;

  // ── Sender operations ───────────────────────────────────────────────

  /// Encrypt a group message using our sender key.
  ///
  /// Wire format: group_id(32) || key_id(4) || msg_number(4) || nonce(12) || ciphertext+tag
  Future<Uint8List> encrypt(Uint8List plaintext) async {
    if (_senderKey == null) {
      throw StateError('No sender key — join or create group first');
    }

    final mk = _senderKey!.nextMessageKey();
    if (mk == null) {
      throw StateError('Sender key chain exhausted');
    }

    final nonce = randomBytes(nonceLength);
    final msgNumber = _senderKey!.messageNumber - 1;

    // Build AD: group_id || key_id || message_number
    final keyIdBytes = ByteData(4)
      ..setUint32(0, _senderKey!.keyId, Endian.little);
    final msgNumBytes = ByteData(4)
      ..setUint32(0, msgNumber, Endian.little);

    final ad = Uint8List.fromList([
      ...groupId,
      ...keyIdBytes.buffer.asUint8List(),
      ...msgNumBytes.buffer.asUint8List(),
    ]);

    final ciphertext = await chacha20Poly1305Encrypt(
      mk,
      plaintext,
      associatedData: ad,
      nonce: nonce,
    );

    return Uint8List.fromList([
      ...groupId,
      ...keyIdBytes.buffer.asUint8List(),
      ...msgNumBytes.buffer.asUint8List(),
      ...ciphertext,
    ]);
  }

  /// Create key distribution messages for group members.
  ///
  /// Each message encrypts our sender key to a member's X25519 key.
  Future<List<SenderKeyMessage>> getKeyDistributionMessages(
    Ed25519KeyPair identity,
    List<Uint8List> memberPublicKeys,
  ) async {
    if (_senderKey == null) {
      throw StateError('No sender key');
    }

    final messages = <SenderKeyMessage>[];
    for (final memberPub in memberPublicKeys) {
      // Encrypt sender key to member (using X25519 DH + HKDF + ChaCha20)
      final ephemeral = await X25519KeyPair.generate();
      final shared = await ephemeral.dh(memberPub);
      final encKey = hkdf(
        shared,
        info: Uint8List.fromList([
          ...utf8.encode('SibnaGroupKeyDistribute_v3'),
        ]),
        length: keyLength,
      );
      final encrypted = await chacha20Poly1305Encrypt(
        encKey,
        _senderKey!.chainKey,
      );

      final msg = SenderKeyMessage(
        groupId: groupId,
        senderPublicKey: identity.publicKey,
        encryptedKey: encrypted,
        signature: Uint8List(64), // placeholder, will be signed
        keyId: _senderKey!.keyId,
      );
      await msg.sign(identity);
      messages.add(msg);
    }

    return messages;
  }

  // ── Receiver operations ─────────────────────────────────────────────

  /// Process a key distribution message and store the sender's key.
  Future<void> processKeyDistribution({
    required SenderKeyMessage msg,
    required X25519KeyPair ourX25519,
    required Uint8List ephemeralPublic,
  }) async {
    if (!await msg.verifySignature()) {
      throw ArgumentError('Invalid signature on key distribution message');
    }

    final shared = await ourX25519.dh(ephemeralPublic);
    final encKey = hkdf(
      shared,
      info: Uint8List.fromList([
        ...utf8.encode('SibnaGroupKeyDistribute_v3'),
      ]),
      length: keyLength,
    );
    final chainKey = await chacha20Poly1305Decrypt(encKey, msg.encryptedKey);

    _senderKeys[msg.senderPublicKey] = SenderKey(
      chainKey: chainKey,
      keyId: msg.keyId,
    );
  }

  /// Decrypt a group message from a specific sender.
  Future<Uint8List> decrypt(
    Uint8List ciphertext,
    Uint8List senderPublicKey,
  ) async {
    if (ciphertext.length < 32 + 4 + 4 + nonceLength + 16) {
      throw ArgumentError('Ciphertext too short');
    }

    var offset = 0;
    final groupIdBytes =
        Uint8List.fromList(ciphertext.sublist(offset, offset + 32));
    offset += 32;

    final keyId = ByteData.sublistView(
      Uint8List.fromList(ciphertext.sublist(offset, offset + 4)),
    ).getUint32(0, Endian.little);
    offset += 4;

    final msgNumber = ByteData.sublistView(
      Uint8List.fromList(ciphertext.sublist(offset, offset + 4)),
    ).getUint32(0, Endian.little);
    offset += 4;

    final encryptedPart = ciphertext.sublist(offset);

    if (!_bytesEqual(groupIdBytes, groupId)) {
      throw ArgumentError('Group ID mismatch');
    }

    final senderKey = _senderKeys[senderPublicKey];
    if (senderKey == null) {
      throw StateError('No sender key for this sender');
    }

    if (senderKey.keyId != keyId) {
      throw ArgumentError(
        'Key ID mismatch: expected ${senderKey.keyId}, got $keyId',
      );
    }

    // Skip ahead if needed
    while (senderKey.messageNumber < msgNumber) {
      final mk = senderKey.nextMessageKey();
      if (mk == null) {
        throw StateError('Sender key chain exhausted');
      }
    }

    final mk = senderKey.nextMessageKey();
    if (mk == null) {
      throw StateError('Sender key chain exhausted');
    }

    final nonce = Uint8List.fromList(encryptedPart.sublist(0, nonceLength));
    final actualCt = encryptedPart.sublist(nonceLength);

    final keyIdBytes = ByteData(4)..setUint32(0, keyId, Endian.little);
    final msgNumBytes = ByteData(4)..setUint32(0, msgNumber, Endian.little);

    final ad = Uint8List.fromList([
      ...groupId,
      ...keyIdBytes.buffer.asUint8List(),
      ...msgNumBytes.buffer.asUint8List(),
    ]);

    return chacha20Poly1305Decrypt(mk, actualCt, associatedData: ad, nonce: nonce);
  }

  // ── Key rotation ────────────────────────────────────────────────────

  /// Rotate to a new sender key.
  SenderKey rotateSenderKey() {
    _keyRotationCount++;
    _senderKey = SenderKey.generate(keyId: _keyRotationCount);
    return _senderKey!;
  }

  @override
  String toString() {
    return 'GroupSession(group_id: ${bytesToHex(groupId).substring(0, 16)}..., '
        'members: ${_senderKeys.length}, '
        'rotations: $_keyRotationCount)';
  }

  bool _bytesEqual(Uint8List a, Uint8List b) => constantTimeEquals(a, b);
}
