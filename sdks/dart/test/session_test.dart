import 'package:test/test.dart';
import 'package:sibna_protocol/sibna_protocol.dart';
import 'dart:typed_data';

void main() {
  group('Session Tests', () {
    test('Session encrypt throws on uninitialized handle', () {
      final s1 = SibnaSession.fromSharedSecret(
        Uint8List.fromList(List.generate(32, (i) => i)), 'local_a', 'remote_b'
      );

      final plaintext = Uint8List.fromList('Hello Dart!'.codeUnits);

      expect(() async => await s1.encrypt(plaintext), throwsA(isA<SibnaError>()));
    });

    test('Session decrypt throws on uninitialized handle', () {
      final s2 = SibnaSession.fromSharedSecret(
        Uint8List.fromList(List.generate(32, (i) => i)), 'local_b', 'remote_a'
      );

      final ct = Uint8List.fromList([0x01, 0x02]);

      expect(() async => await s2.decrypt(ct), throwsA(isA<SibnaError>()));
    });

    test('Session rejects empty plaintext', () {
      final s1 = SibnaSession.fromSharedSecret(
        Uint8List.fromList(List.generate(32, (i) => i)), 'a', 'b'
      );
      
      expect(() => s1.encrypt(Uint8List(0)), throwsA(isA<ValidationError>()));
    });

    test('Session rejects empty ciphertext', () {
      final s2 = SibnaSession.fromSharedSecret(
        Uint8List.fromList(List.generate(32, (i) => i)), 'b', 'a'
      );
      
      expect(() => s2.decrypt(Uint8List(0)), throwsA(isA<ValidationError>()));
    });

    test('Session stats verification', () {
      final s1 = SibnaSession.fromSharedSecret(
        Uint8List.fromList(List.generate(32, (i) => i)), 'a', 'b'
      );
      
      final stats = s1.stats;
      expect(stats['messagesSent'], equals(0));
      expect(stats['messagesReceived'], equals(0));
    });
  });
}
