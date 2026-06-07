import 'package:test/test.dart';
import 'package:sibna_protocol/sibna_protocol.dart';
import 'dart:typed_data';

void main() {
  group('IdentityKeyPair (pure Dart)', () {
    test('fromPublicKeys creates valid identity', () {
      final ed25519Pub = Uint8List.fromList(List.generate(32, (i) => i));
      final x25519Pub = Uint8List.fromList(List.generate(32, (i) => i + 32));

      final identity = IdentityKeyPair.fromPublicKeys(ed25519Pub, x25519Pub);
      expect(identity.ed25519PublicKey.length, 32);
      expect(identity.x25519PublicKey.length, 32);
      expect(identity.fingerprint.isNotEmpty, isTrue);
    });

    test('Multiple identities with different keys are unique', () {
      final id1 = IdentityKeyPair.fromPublicKeys(
        Uint8List.fromList(List.generate(32, (i) => i)),
        Uint8List.fromList(List.generate(32, (i) => i + 32)),
      );
      final id2 = IdentityKeyPair.fromPublicKeys(
        Uint8List.fromList(List.generate(32, (i) => i + 1)),
        Uint8List.fromList(List.generate(32, (i) => i + 33)),
      );
      expect(id1, isNot(equals(id2)));
    });

    test('Same keys produce equal identities', () {
      final keys1 = Uint8List.fromList(List.generate(32, (i) => i));
      final keys2 = Uint8List.fromList(List.generate(32, (i) => i + 100));
      final id1 = IdentityKeyPair.fromPublicKeys(keys1, keys2);
      final id2 = IdentityKeyPair.fromPublicKeys(
        Uint8List.fromList(keys1),
        Uint8List.fromList(keys2),
      );
      expect(id1, equals(id2));
    });

    test('verifySignature throws until FFI is wired', () {
      final identity = IdentityKeyPair.fromPublicKeys(
        Uint8List(32),
        Uint8List(32),
      );
      expect(
        () => identity.verifySignature(Uint8List(32), Uint8List(64)),
        throwsA(isA<UnimplementedError>()),
      );
    });
  });
}
