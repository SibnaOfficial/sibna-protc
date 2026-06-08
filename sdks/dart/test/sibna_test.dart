import 'package:test/test.dart';
import 'package:sibna/sibna.dart';
import 'dart:typed_data';

void main() {
  group('Ed25519 Key Pair', () {
    test('generate produces valid key pair', () async {
      final kp = await Ed25519KeyPair.generate();
      expect(kp.publicKey.length, equals(32));
    });

    test('fromSeed produces deterministic keys', () async {
      final seed = randomBytes(32);
      final kp1 = await Ed25519KeyPair.fromSeed(seed);
      final kp2 = await Ed25519KeyPair.fromSeed(seed);
      expect(kp1.publicKey, equals(kp2.publicKey));
    });

    test('sign and verify', () async {
      final kp = await Ed25519KeyPair.generate();
      final data = Uint8List.fromList([1, 2, 3, 4]);
      final sig = await kp.sign(data);
      expect(sig.length, equals(64));
      expect(await kp.verify(data, sig), isTrue);
    });

    test('verify rejects wrong data', () async {
      final kp = await Ed25519KeyPair.generate();
      final data = Uint8List.fromList([1, 2, 3, 4]);
      final sig = await kp.sign(data);
      expect(
        await kp.verify(Uint8List.fromList([5, 6, 7, 8]), sig),
        isFalse,
      );
    });

    test('verifyWithKey with raw public key bytes', () async {
      final kp = await Ed25519KeyPair.generate();
      final data = Uint8List.fromList([10, 20, 30]);
      final sig = await kp.sign(data);
      expect(
        await Ed25519KeyPair.verifyWithKey(kp.publicKey, data, sig),
        isTrue,
      );
    });
  });

  group('X25519 Key Pair', () {
    test('generate produces valid key pair', () async {
      final kp = await X25519KeyPair.generate();
      expect(kp.publicKey.length, equals(32));
    });

    test('fromSeed produces deterministic keys', () async {
      final seed = randomBytes(32);
      final kp1 = await X25519KeyPair.fromSeed(seed);
      final kp2 = await X25519KeyPair.fromSeed(seed);
      expect(kp1.publicKey, equals(kp2.publicKey));
    });

    test('DH produces shared secret', () async {
      final alice = await X25519KeyPair.generate();
      final bob = await X25519KeyPair.generate();
      final sharedAlice = await alice.dh(bob.publicKey);
      final sharedBob = await bob.dh(alice.publicKey);
      expect(sharedAlice, equals(sharedBob));
      expect(sharedAlice.length, equals(32));
    });

    test('rejects low-order point', () async {
      final kp = await X25519KeyPair.generate();
      final lowOrder = Uint8List(32); // all zeros
      expect(() => kp.dh(lowOrder), throwsArgumentError);
    });

    test('rejects short public key', () async {
      final kp = await X25519KeyPair.generate();
      expect(() => kp.dh(Uint8List(16)), throwsArgumentError);
    });
  });

  group('HKDF-SHA256', () {
    test('basic HKDF', () {
      final ikm = randomBytes(32);
      final salt = randomBytes(32);
      final info = Uint8List.fromList([1, 2, 3]);
      final result = hkdf(ikm, salt: salt, info: info, length: 32);
      expect(result.length, equals(32));
    });

    test('deterministic output', () {
      final ikm = Uint8List(32)..fillRange(0, 32, 0xAB);
      final result1 = hkdf(ikm, length: 64);
      final result2 = hkdf(ikm, length: 64);
      expect(result1, equals(result2));
    });

    test('different salts produce different output', () {
      final ikm = randomBytes(32);
      final r1 = hkdf(ikm, salt: Uint8List(32), length: 32);
      final r2 = hkdf(ikm, salt: randomBytes(32), length: 32);
      expect(r1, isNot(equals(r2)));
    });
  });

  group('HMAC-SHA256', () {
    test('basic HMAC', () {
      final key = randomBytes(32);
      final data = Uint8List.fromList([1, 2, 3]);
      final result = hmacSha256(key, data);
      expect(result.length, equals(32));
    });

    test('deterministic', () {
      final key = Uint8List(32)..fillRange(0, 32, 0xAA);
      final data = Uint8List.fromList([10, 20, 30]);
      expect(hmacSha256(key, data), equals(hmacSha256(key, data)));
    });
  });

  group('SHA-256 / SHA-512', () {
    test('SHA-256', () {
      final data = Uint8List.fromList([1, 2, 3]);
      expect(sha256Hash(data).length, equals(32));
    });

    test('SHA-512', () {
      final data = Uint8List.fromList([1, 2, 3]);
      expect(sha512Hash(data).length, equals(64));
    });
  });

  group('ChaCha20-Poly1305', () {
    test('encrypt and decrypt round trip', () async {
      final key = randomBytes(32);
      final plaintext = Uint8List.fromList([72, 101, 108, 108, 111]);
      final encrypted = await chacha20Poly1305Encrypt(key, plaintext);
      final decrypted = await chacha20Poly1305Decrypt(key, encrypted);
      expect(decrypted, equals(plaintext));
    });

    test('with associated data', () async {
      final key = randomBytes(32);
      final plaintext = Uint8List.fromList([1, 2, 3]);
      final ad = Uint8List.fromList([4, 5, 6]);
      final encrypted = await chacha20Poly1305Encrypt(
        key,
        plaintext,
        associatedData: ad,
      );
      final decrypted = await chacha20Poly1305Decrypt(
        key,
        encrypted,
        associatedData: ad,
      );
      expect(decrypted, equals(plaintext));
    });

    test('wrong key fails to decrypt', () async {
      final key1 = randomBytes(32);
      final key2 = randomBytes(32);
      final plaintext = Uint8List.fromList([1, 2, 3]);
      final encrypted = await chacha20Poly1305Encrypt(key1, plaintext);
      expect(
        () => chacha20Poly1305Decrypt(key2, encrypted),
        throwsA(anything),
      );
    });

    test('wrong AD fails to decrypt', () async {
      final key = randomBytes(32);
      final plaintext = Uint8List.fromList([1, 2, 3]);
      final encrypted = await chacha20Poly1305Encrypt(
        key,
        plaintext,
        associatedData: Uint8List.fromList([4, 5, 6]),
      );
      expect(
        () => chacha20Poly1305Decrypt(
          key,
          encrypted,
          associatedData: Uint8List.fromList([7, 8, 9]),
        ),
        throwsA(anything),
      );
    });

    test('output format: nonce(12) || ciphertext || tag(16)', () async {
      final key = randomBytes(32);
      final plaintext = Uint8List(42);
      final encrypted = await chacha20Poly1305Encrypt(key, plaintext);
      // nonce(12) + plaintext(42) + tag(16) = 70
      expect(encrypted.length, equals(12 + 42 + 16));
    });
  });

  group('ChaCha20-Poly1305 with explicit nonce', () {
    test('encrypt with explicit nonce and decrypt', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final plaintext = Uint8List.fromList([10, 20, 30]);
      final encrypted = await chacha20Poly1305Encrypt(
        key,
        plaintext,
        nonce: nonce,
      );
      final decrypted = await chacha20Poly1305Decrypt(
        key,
        encrypted.sublist(12), // strip nonce
        nonce: nonce,
      );
      expect(decrypted, equals(plaintext));
    });
  });

  group('Blake3 Hash', () {
    test('produces 32-byte output', () async {
      final parts = [
        Uint8List.fromList([1, 2, 3]),
        Uint8List.fromList([4, 5, 6]),
      ];
      final hash = await blake3Hash(parts);
      expect(hash.length, equals(32));
    });

    test('deterministic', () async {
      final parts = [Uint8List.fromList([10, 20])];
      final h1 = await blake3Hash(parts);
      final h2 = await blake3Hash(parts);
      expect(h1, equals(h2));
    });
  });

  group('Random Bytes', () {
    test('produces correct length', () {
      expect(randomBytes(32).length, equals(32));
      expect(randomBytes(64).length, equals(64));
    });

    test('produces different output each time', () {
      expect(randomBytes(32), isNot(equals(randomBytes(32))));
    });
  });

  group('Low-Order Point Rejection', () {
    test('rejects all 8 known low-order points', () async {
      final kp = await X25519KeyPair.generate();
      for (final point in lowOrderPoints) {
        expect(
          () => kp.dh(point),
          throwsArgumentError,
          reason: 'Should reject low-order point',
        );
      }
    });
  });

  group('Constant-Time Equals', () {
    test('equal arrays', () {
      final a = Uint8List.fromList([1, 2, 3]);
      expect(constantTimeEquals(a, Uint8List.fromList([1, 2, 3])), isTrue);
    });

    test('different arrays', () {
      final a = Uint8List.fromList([1, 2, 3]);
      expect(constantTimeEquals(a, Uint8List.fromList([1, 2, 4])), isFalse);
    });

    test('different lengths', () {
      final a = Uint8List.fromList([1, 2, 3]);
      expect(constantTimeEquals(a, Uint8List.fromList([1, 2])), isFalse);
    });
  });

  group('Hex Encoding', () {
    test('bytesToHex and hexToBytes round trip', () {
      final original = Uint8List.fromList([0, 1, 15, 16, 255]);
      final hex = bytesToHex(original);
      expect(hex, equals('00010f10ff'));
      expect(hexToBytes(hex), equals(original));
    });
  });

  group('Chain Key', () {
    test('next_message_key derives key and advances chain', () {
      final ck = ChainKey(key: randomBytes(32));
      final result = ck.nextMessageKey();
      expect(result, isNotNull);
      final (mk, nextCk) = result!;
      expect(mk.length, equals(32));
      expect(nextCk.index, equals(1));
    });

    test('chain exhausts at maxChainMessages', () {
      final ck = ChainKey(key: randomBytes(32), maxMessages: 2);
      final r1 = ck.nextMessageKey();
      expect(r1, isNotNull);
      final (_, r2Ck) = r1!;
      final r2 = r2Ck.nextMessageKey();
      expect(r2, isNotNull);
      final (_, r3Ck) = r2!;
      expect(r3Ck.nextMessageKey(), isNull);
    });
  });

  group('Safety Number', () {
    test('calculate produces 80-digit number', () async {
      final alice = randomBytes(32);
      final bob = randomBytes(32);
      final sn = SafetyNumber.calculate(alice, bob);
      expect(sn.asString().length, equals(80));
    });

    test('symmetric ordering', () async {
      final a = randomBytes(32);
      final b = randomBytes(32);
      final sn1 = SafetyNumber.calculate(a, b);
      final sn2 = SafetyNumber.calculate(b, a);
      expect(sn1.fingerprint, equals(sn2.fingerprint));
    });

    test('fromString round trip', () async {
      final alice = randomBytes(32);
      final bob = randomBytes(32);
      final sn = SafetyNumber.calculate(alice, bob);
      final parsed = SafetyNumber.fromString(sn.asString());
      expect(parsed.fingerprint, equals(sn.fingerprint));
    });

    test('qr_data is 36 bytes', () async {
      final alice = randomBytes(32);
      final bob = randomBytes(32);
      final sn = SafetyNumber.calculate(alice, bob);
      expect(sn.qrData().length, equals(36));
    });

    test('verify constant-time', () async {
      final alice = randomBytes(32);
      final bob = randomBytes(32);
      final sn1 = SafetyNumber.calculate(alice, bob);
      final sn2 = SafetyNumber.calculate(alice, bob);
      expect(sn1.verify(sn2), isTrue);
    });

    test('formatted display', () async {
      final alice = randomBytes(32);
      final bob = randomBytes(32);
      final sn = SafetyNumber.calculate(alice, bob);
      final display = sn.formatted();
      expect(display.contains(' '), isTrue);
    });
  });
}
