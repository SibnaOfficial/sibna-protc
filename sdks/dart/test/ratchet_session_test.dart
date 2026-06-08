import 'package:test/test.dart';
import 'package:sibna/sibna.dart';
import 'dart:typed_data';

void main() {
  group('Double Ratchet', () {
    test('from_shared_secret creates valid state', () async {
      final secret = randomBytes(32);
      final local = randomBytes(32);
      final remote = randomBytes(32);

      final dr = await DoubleRatchet.fromSharedSecret(
        sharedSecret: secret,
        localDhPrivate: local,
        remoteDhPublic: remote,
        roleIsInitiator: true,
      );

      expect(dr.rootKey.length, equals(32));
      expect(dr.sendingChain, isNotNull);
      expect(dr.receivingChain, isNull);
      expect(dr.messagesSent, equals(0));
    });

    test('responder has receiving chain, no sending chain', () async {
      final secret = randomBytes(32);
      final local = randomBytes(32);
      final remote = randomBytes(32);

      final dr = await DoubleRatchet.fromSharedSecret(
        sharedSecret: secret,
        localDhPrivate: local,
        remoteDhPublic: remote,
        roleIsInitiator: false,
      );

      expect(dr.sendingChain, isNull);
      expect(dr.receivingChain, isNotNull);
    });

    test('ratchet encrypt creates valid wire format', () async {
      final secret = randomBytes(32);
      final localKp = await X25519KeyPair.generate();
      final remoteKp = await X25519KeyPair.generate();

      final dr = await DoubleRatchet.fromSharedSecret(
        sharedSecret: secret,
        localDhPrivate: await localKp.privateKey,
        remoteDhPublic: remoteKp.publicKey,
        roleIsInitiator: true,
      );

      final plaintext = Uint8List.fromList([72, 101, 108, 108, 111]);
      final encrypted = await dr.ratchetEncrypt(plaintext);

      // Wire format: dh_public(32) || msg_num(4) || nonce(12) || ct+tag
      expect(
        encrypted.length,
        greaterThanOrEqualTo(32 + 4 + 12 + 16 + plaintext.length),
      );
      expect(dr.messagesSent, equals(1));
    });

    test('encrypt then decrypt round trip (initiator)', () async {
      final aliceKp = await X25519KeyPair.generate();
      final bobKp = await X25519KeyPair.generate();
      final sharedSecret = randomBytes(32);

      // Alice encrypts
      final aliceDr = await DoubleRatchet.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await aliceKp.privateKey,
        remoteDhPublic: bobKp.publicKey,
        roleIsInitiator: true,
      );

      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
      final encrypted = await aliceDr.ratchetEncrypt(plaintext);

      // Bob decrypts (responder - no sending chain initially)
      final bobDr = await DoubleRatchet.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await bobKp.privateKey,
        remoteDhPublic: aliceKp.publicKey,
        roleIsInitiator: false,
      );

      final decrypted = await bobDr.ratchetDecrypt(encrypted);
      expect(decrypted, equals(plaintext));
    });

    test('bidirectional ratcheting', () async {
      final aliceKp = await X25519KeyPair.generate();
      final bobKp = await X25519KeyPair.generate();
      final sharedSecret = randomBytes(32);

      final aliceDr = await DoubleRatchet.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await aliceKp.privateKey,
        remoteDhPublic: bobKp.publicKey,
        roleIsInitiator: true,
      );

      final bobDr = await DoubleRatchet.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await bobKp.privateKey,
        remoteDhPublic: aliceKp.publicKey,
        roleIsInitiator: false,
      );

      // Alice sends
      final m1 = await aliceDr.ratchetEncrypt(Uint8List.fromList([1]));
      final d1 = await bobDr.ratchetDecrypt(m1);
      expect(d1, equals(Uint8List.fromList([1])));

      // Bob replies (triggers DH ratchet on both sides)
      final m2 = await bobDr.ratchetEncrypt(Uint8List.fromList([2]));
      final d2 = await aliceDr.ratchetDecrypt(m2);
      expect(d2, equals(Uint8List.fromList([2])));

      // Alice sends again
      final m3 = await aliceDr.ratchetEncrypt(Uint8List.fromList([3]));
      final d3 = await bobDr.ratchetDecrypt(m3);
      expect(d3, equals(Uint8List.fromList([3])));
    });

    test('msg_num matches sending chain index before advance', () async {
      final aliceKp = await X25519KeyPair.generate();
      final bobKp = await X25519KeyPair.generate();
      final sharedSecret = randomBytes(32);

      final aliceDr = await DoubleRatchet.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await aliceKp.privateKey,
        remoteDhPublic: bobKp.publicKey,
        roleIsInitiator: true,
      );

      // Before any message, sending chain index is 0
      expect(aliceDr.sendingChain!.index, equals(0));

      final m1 = await aliceDr.ratchetEncrypt(Uint8List.fromList([1]));
      // After first message, msg_num in wire was 0 (index before advance)
      // Sending chain index is now 1
      expect(aliceDr.sendingChain!.index, equals(1));

      // Check msg_num in wire: dh_public(32) || msg_num(4)
      final msgNumBytes = m1.sublist(32, 36);
      final msgNum =
          ByteData.sublistView(Uint8List.fromList(msgNumBytes))
              .getUint32(0, Endian.little);
      expect(msgNum, equals(0));
    });
  });

  group('X3DH', () {
    test('initiator and responder produce same shared secret', () async {
      final aliceIdentity = await X25519KeyPair.generate();
      final aliceEphemeral = await X25519KeyPair.generate();
      final bobIdentity = await X25519KeyPair.generate();
      final bobSignedPrekey = await X25519KeyPair.generate();

      final bobBundle = PreKeyBundle(
        identityKey: randomBytes(32), // Ed25519
        x25519IdentityKey: bobIdentity.publicKey,
        signedPrekey: bobSignedPrekey.publicKey,
        signedPrekeySignature: Uint8List(64), // dummy
      );

      final initiatorResult = await x3DHInitiator(
        identityKeypair: aliceIdentity,
        ephemeralKeypair: aliceEphemeral,
        peerBundle: bobBundle,
      );

      final responderResult = await x3DHResponder(
        identityKeypair: bobIdentity,
        signedPrekeypair: bobSignedPrekey,
        peerIdentity: aliceIdentity.publicKey,
        peerEphemeral: aliceEphemeral.publicKey,
      );

      expect(
        initiatorResult.sharedSecret,
        equals(responderResult.sharedSecret),
      );
    });

    test('with one-time prekey', () async {
      final aliceIdentity = await X25519KeyPair.generate();
      final aliceEphemeral = await X25519KeyPair.generate();
      final bobIdentity = await X25519KeyPair.generate();
      final bobSignedPrekey = await X25519KeyPair.generate();
      final bobOneTimePrekey = await X25519KeyPair.generate();

      final bobBundle = PreKeyBundle(
        identityKey: randomBytes(32),
        x25519IdentityKey: bobIdentity.publicKey,
        signedPrekey: bobSignedPrekey.publicKey,
        signedPrekeySignature: Uint8List(64),
        onetimePrekey: bobOneTimePrekey.publicKey,
      );

      final initiatorResult = await x3DHInitiator(
        identityKeypair: aliceIdentity,
        ephemeralKeypair: aliceEphemeral,
        peerBundle: bobBundle,
      );

      final responderResult = await x3DHResponder(
        identityKeypair: bobIdentity,
        signedPrekeypair: bobSignedPrekey,
        onetimePrekeypair: bobOneTimePrekey,
        peerIdentity: aliceIdentity.publicKey,
        peerEphemeral: aliceEphemeral.publicKey,
      );

      expect(
        initiatorResult.sharedSecret,
        equals(responderResult.sharedSecret),
      );
    });
  });

  group('Session', () {
    test('from_shared_secret creates working session', () async {
      final sharedSecret = randomBytes(32);
      final localKp = await X25519KeyPair.generate();
      final remoteKp = await X25519KeyPair.generate();

      final session = await Session.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await localKp.privateKey,
        remoteDhPublic: remoteKp.publicKey,
        roleIsInitiator: true,
      );

      expect(session.isEstablished, isTrue);
      expect(session.messagesSent, equals(0));

      final ct = await session.encrypt(Uint8List.fromList([1, 2, 3]));
      expect(ct.length, greaterThan(0));
      expect(session.messagesSent, equals(1));
    });

    test('encrypt/decrypt round trip via from_shared_secret', () async {
      final sharedSecret = randomBytes(32);
      final aliceKp = await X25519KeyPair.generate();
      final bobKp = await X25519KeyPair.generate();

      final aliceSession = await Session.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await aliceKp.privateKey,
        remoteDhPublic: bobKp.publicKey,
        roleIsInitiator: true,
      );

      final bobSession = await Session.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await bobKp.privateKey,
        remoteDhPublic: aliceKp.publicKey,
        roleIsInitiator: false,
      );

      final plaintext = Uint8List.fromList([72, 101, 108, 108, 111]);
      final encrypted = await aliceSession.encrypt(plaintext);
      final decrypted = await bobSession.decrypt(encrypted);
      expect(decrypted, equals(plaintext));
    });

    test('throws when not established', () async {
      final session = Session();
      expect(
        () => session.encrypt(Uint8List.fromList([1])),
        throwsStateError,
      );
    });

    test('export state', () async {
      final sharedSecret = randomBytes(32);
      final localKp = await X25519KeyPair.generate();
      final remoteKp = await X25519KeyPair.generate();

      final session = await Session.fromSharedSecret(
        sharedSecret: sharedSecret,
        localDhPrivate: await localKp.privateKey,
        remoteDhPublic: remoteKp.publicKey,
        roleIsInitiator: true,
      );

      final state = session.exportState();
      expect(state, isNotNull);
      expect(state!['sessionId'], isA<String>());
      expect(state['rootKey'], isA<String>());
    });
  });

  group('Group Session', () {
    test('create and encrypt', () async {
      final gs = GroupSession.create();
      expect(gs.groupId.length, equals(32));

      final plaintext = Uint8List.fromList([1, 2, 3]);
      final ct = await gs.encrypt(plaintext);
      expect(ct.length, greaterThan(plaintext.length));
    });

    test('rotate sender key', () async {
      final gs = GroupSession.create();
      final key1 = gs.senderKey;
      final key2 = gs.rotateSenderKey();
      expect(key1, isNot(equals(key2)));
      expect(key2.keyId, equals(1));
    });

    test('sender key message serialization', () async {
      final identity = await Ed25519KeyPair.generate();
      final msg = SenderKeyMessage(
        groupId: randomBytes(32),
        senderPublicKey: identity.publicKey,
        encryptedKey: randomBytes(48),
        signature: Uint8List(64),
        keyId: 0,
      );

      final bytes = msg.toBytes();
      final parsed = SenderKeyMessage.fromBytes(bytes);

      expect(parsed.groupId, equals(msg.groupId));
      expect(parsed.keyId, equals(msg.keyId));
      expect(parsed.encryptedKey, equals(msg.encryptedKey));
    });
  });

  group('Identity Key Derivation', () {
    test('deriveIdentityKeys produces valid key pairs', () async {
      final seed = randomBytes(32);
      final (edKp, xKp) = await deriveIdentityKeys(seed);

      expect(edKp.publicKey.length, equals(32));
      expect(xKp.publicKey.length, equals(32));

      // Deterministic
      final (edKp2, xKp2) = await deriveIdentityKeys(seed);
      expect(edKp.publicKey, equals(edKp2.publicKey));
      expect(xKp.publicKey, equals(xKp2.publicKey));
    });
  });
}
