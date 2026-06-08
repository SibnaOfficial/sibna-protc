/// Sibna Protocol v3.0.1 — Double Ratchet Implementation
///
/// Matches the Rust core exactly:
///   - ChainKey derivation: HMAC-SHA256(chain_key, 0x01) = message_key,
///                          HMAC-SHA256(chain_key, 0x02) = next_chain_key
///   - Root key KDF: HKDF(root_key, dh_output, "SibnaRatchet_v3")
///   - Initial session KDF: HKDF(shared_secret, salt="SibnaSession_v3",
///                                info="SibnaRootAndChainKey_v3")
///   - Wire format: dh_public(32) || message_number(4) || nonce(12) || ciphertext+tag
import 'dart:convert';
import 'dart:typed_data';

import 'crypto.dart';

// ── Constants ────────────────────────────────────────────────────────────────

final Uint8List _messageKeySeed = Uint8List.fromList([0x01]);
final Uint8List _chainKeySeed = Uint8List.fromList([0x02]);
final Uint8List _headerKeySeed = Uint8List.fromList([0x03]);

final Uint8List _initialKdfSalt = Uint8List.fromList([
  ...utf8.encode('SibnaSession_v3'),
]);
final Uint8List _initialKdfInfo = Uint8List.fromList([
  ...utf8.encode('SibnaRootAndChainKey_v3'),
]);
final Uint8List _dhRatchetInfo = Uint8List.fromList([
  ...utf8.encode('SibnaRatchet_v3'),
]);

const int maxChainMessages = 4000;
const int maxSkippedMessages = 2000;

// ── Chain Key ────────────────────────────────────────────────────────────────

/// Symmetric ratchet chain key.
class ChainKey {
  final Uint8List key;
  final int index;
  final int maxMessages;

  ChainKey({
    required this.key,
    this.index = 0,
    this.maxMessages = maxChainMessages,
  });

  /// Derive the next message key and advance the chain.
  ///
  /// Returns (messageKey, nextChainKey) or null if chain exhausted.
  (Uint8List, ChainKey)? nextMessageKey() {
    if (index >= maxMessages) return null;

    final messageKey = hmacSha256(key, _messageKeySeed);
    final nextChainKey = hmacSha256(key, _chainKeySeed);

    return (
      messageKey,
      ChainKey(
        key: nextChainKey,
        index: index + 1,
        maxMessages: maxMessages,
      ),
    );
  }

  /// Derive the header key from the current chain key.
  Uint8List deriveHeaderKey() {
    return hmacSha256(key, _headerKeySeed);
  }

  /// Number of messages remaining in this chain.
  int get remainingMessages => (maxMessages - index).clamp(0, maxMessages);
}

// ── Double Ratchet Session ──────────────────────────────────────────────────

/// Double Ratchet encryption state machine.
///
/// Manages root_key, sending_chain, receiving_chain, DH key pairs,
/// and skipped message key cache for out-of-order delivery.
class DoubleRatchet {
  Uint8List rootKey;
  ChainKey? sendingChain;
  ChainKey? receivingChain;
  Uint8List? dhLocalPrivate;
  Uint8List? dhLocalPublic;
  Uint8List? dhRemotePublic;
  int previousCounter;
  int maxSkip;
  final Map<(Uint8List, int), Uint8List> skippedKeys;
  int messagesSent;
  int messagesReceived;

  DoubleRatchet({
    required this.rootKey,
    this.sendingChain,
    this.receivingChain,
    this.dhLocalPrivate,
    this.dhLocalPublic,
    this.dhRemotePublic,
    this.previousCounter = 0,
    this.maxSkip = maxSkippedMessages,
    Map<(Uint8List, int), Uint8List>? skippedKeys,
    this.messagesSent = 0,
    this.messagesReceived = 0,
  }) : skippedKeys = skippedKeys ?? {};

  /// Create initial DoubleRatchet state from X3DH shared secret.
  static Future<DoubleRatchet> fromSharedSecret({
    required Uint8List sharedSecret,
    required Uint8List localDhPrivate,
    required Uint8List remoteDhPublic,
    required bool roleIsInitiator,
  }) async {
    if (sharedSecret.length != keyLength) {
      throw ArgumentError('shared_secret must be 32 bytes');
    }

    final okm = hkdf(
      sharedSecret,
      salt: _initialKdfSalt,
      info: _initialKdfInfo,
      length: 64,
    );
    final rootKey = okm.sublist(0, 32);
    final chainKeyBytes = okm.sublist(32);

    final localKp = await X25519KeyPair.fromPrivateBytes(localDhPrivate);
    final localPub = localKp.publicKey;

    ChainKey? sending;
    ChainKey? receiving;

    if (roleIsInitiator) {
      sending = ChainKey(key: chainKeyBytes);
      receiving = null;
    } else {
      sending = null;
      receiving = ChainKey(key: chainKeyBytes);
    }

    return DoubleRatchet(
      rootKey: rootKey,
      sendingChain: sending,
      receivingChain: receiving,
      dhLocalPrivate: localDhPrivate,
      dhLocalPublic: localPub,
      dhRemotePublic: remoteDhPublic,
    );
  }

  /// KDF_RK: derive new root_key and chain_key from DH output.
  (Uint8List, Uint8List) _kdfRk(Uint8List dhOut) {
    final okm = hkdf(
      dhOut,
      salt: rootKey,
      info: _dhRatchetInfo,
      length: 64,
    );
    return (okm.sublist(0, 32), okm.sublist(32));
  }

  /// Perform a DH ratchet step when a new remote key is received.
  ///
  /// 1. Receive step: DH(existing_local_priv, new_remote_pub) -> root + receiving_chain
  /// 2. Send step: generate new_local, DH(new_local_priv, new_remote_pub) -> root + sending_chain
  Future<void> _dhRatchetStep() async {
    // Save previous receiving chain for skipped key tracking
    if (receivingChain != null) {
      previousCounter = receivingChain!.index;
    }

    // --- Receive step: use EXISTING local key ---
    final existingLocal =
        await X25519KeyPair.fromPrivateBytes(dhLocalPrivate!);
    final dhOutRecv = await existingLocal.dh(dhRemotePublic!);
    final recvResult = _kdfRk(dhOutRecv);
    rootKey = recvResult.$1;
    receivingChain = ChainKey(key: recvResult.$2);

    // --- Send step: generate new key pair for future sends ---
    final newLocal = await X25519KeyPair.generate();
    dhLocalPrivate = await newLocal.privateKey;
    dhLocalPublic = newLocal.publicKey;
    final dhOutSend = await newLocal.dh(dhRemotePublic!);
    final sendResult = _kdfRk(dhOutSend);
    rootKey = sendResult.$1;
    sendingChain = ChainKey(key: sendResult.$2);
  }

  /// Check if we have a skipped message key for this (pub, nr).
  Uint8List? _trySkippedMessageKey(Uint8List dhPublic, int messageNumber) {
    final key = (dhPublic, messageNumber);
    final mk = skippedKeys[key];
    if (mk != null) {
      skippedKeys.remove(key);
      return mk;
    }
    return null;
  }

  /// Skip message keys in the receiving chain until [until].
  void _skipMessageKeys(int until) {
    if (receivingChain == null) return;

    while (receivingChain!.index < until) {
      final result = receivingChain!.nextMessageKey();
      if (result == null) break;

      final mk = result.$1;
      final nextCk = result.$2;
      skippedKeys[(dhRemotePublic!, receivingChain!.index)] = mk;

      if (skippedKeys.length > maxSkip) {
        // Evict oldest entries
        final oldestKey = skippedKeys.keys.first;
        skippedKeys.remove(oldestKey);
      }
      receivingChain = nextCk;
    }
  }

  /// Encrypt a message using the sending chain.
  ///
  /// Wire format: dh_public(32) || message_number(4) || nonce(12) || ciphertext+tag
  Future<Uint8List> ratchetEncrypt(
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) async {
    // If no sending chain, do a DH ratchet step to create one
    if (sendingChain == null) {
      if (dhRemotePublic == null) {
        throw StateError('No remote DH public key');
      }
      final newLocal = await X25519KeyPair.generate();
      dhLocalPrivate = await newLocal.privateKey;
      dhLocalPublic = newLocal.publicKey;
      final dhOut = await newLocal.dh(dhRemotePublic!);
      final result = _kdfRk(dhOut);
      rootKey = result.$1;
      sendingChain = ChainKey(key: result.$2);
    }

    // Capture the message number BEFORE advancing the chain.
    final msgNum = sendingChain!.index;

    final result = sendingChain!.nextMessageKey();
    if (result == null) {
      throw StateError('Chain exhausted');
    }
    final messageKey = result.$1;
    sendingChain = result.$2;

    messagesSent++;

    // Build header: dh_public(32) + message_number(4 LE)
    final msgNumBytes = ByteData(4)
      ..setUint32(0, msgNum & 0xFFFFFFFF, Endian.little);
    final header = Uint8List.fromList([
      ...dhLocalPublic!,
      ...msgNumBytes.buffer.asUint8List(),
    ]);

    // Full AD = caller's AD + header
    final ad = associatedData ?? Uint8List(0);
    final fullAd = Uint8List.fromList([...ad, ...header]);

    // Encrypt: returns nonce(12) || ciphertext+tag
    final ciphertext = await chacha20Poly1305Encrypt(
      messageKey,
      plaintext,
      associatedData: fullAd,
    );

    return Uint8List.fromList([...header, ...ciphertext]);
  }

  /// Decrypt a message using the receiving chain.
  ///
  /// Wire format: dh_public(32) || message_number(4) || nonce(12) || ciphertext+tag
  Future<Uint8List> ratchetDecrypt(
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) async {
    if (ciphertext.length < keyLength + 4 + nonceLength + tagLength) {
      throw ArgumentError('Ciphertext too short');
    }

    final remoteDhPub = Uint8List.fromList(ciphertext.sublist(0, keyLength));
    final msgNumBytes = ciphertext.sublist(keyLength, keyLength + 4);
    final msgNum =
        ByteData.sublistView(Uint8List.fromList(msgNumBytes))
            .getUint32(0, Endian.little);
    final encryptedPart = ciphertext.sublist(keyLength + 4);

    // Try skipped key first
    Uint8List? mk = _trySkippedMessageKey(remoteDhPub, msgNum);

    if (mk == null) {
      // Check if this is from a new remote key (DH ratchet step needed)
      if (dhRemotePublic == null ||
          !_bytesEqual(remoteDhPub, dhRemotePublic!)) {
        // Discard old receiving chain and skipped keys (forward secrecy)
        receivingChain = null;
        skippedKeys.clear();
        // Perform DH ratchet: receive step + send step
        dhRemotePublic = remoteDhPub;
        await _dhRatchetStep();
      }

      // Skip ahead to the needed message number in the new receiving chain
      if (receivingChain != null) {
        _skipMessageKeys(msgNum);
        final result = receivingChain!.nextMessageKey();
        if (result == null) {
          throw StateError('Receiving chain exhausted');
        }
        mk = result.$1;
        receivingChain = result.$2;
      } else {
        throw StateError('No receiving chain');
      }
    }

    // Build header for AD verification
    final msgNumBytesForHeader = ByteData(4)
      ..setUint32(0, msgNum & 0xFFFFFFFF, Endian.little);
    final header = Uint8List.fromList([
      ...remoteDhPub,
      ...msgNumBytesForHeader.buffer.asUint8List(),
    ]);
    final ad = associatedData ?? Uint8List(0);
    final fullAd = Uint8List.fromList([...ad, ...header]);

    final plaintext = await chacha20Poly1305Decrypt(
      mk,
      encryptedPart,
      associatedData: fullAd,
    );

    messagesReceived++;
    return plaintext;
  }

  bool _bytesEqual(Uint8List a, Uint8List b) {
    return constantTimeEquals(a, b);
  }
}
