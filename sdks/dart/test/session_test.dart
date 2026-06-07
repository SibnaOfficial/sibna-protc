import 'package:test/test.dart';
import 'package:sibna_protocol/sibna_protocol.dart';
import 'dart:typed_data';

void main() {
  group('Session Tests', () {
    late SibnaContext context;
    late Uint8List sharedSecret;

    setUpAll(() async {
      await SibnaProtocol.initialize();
      context = await SibnaContext.create();
    });

    tearDownAll(() async {
      context.dispose();
      SibnaProtocol.cleanup();
    });

    setUp(() {
      sharedSecret = Uint8List.fromList(List.generate(32, (i) => i));
    });

    test('Session encrypt throws on uninitialized handle', () {
      // fromSharedSecret creates a session with null handles
      final s1 = SibnaSession.fromSharedSecret(
        sharedSecret, 'local_a', 'remote_b'
      );

      final plaintext = Uint8List.fromList('Hello Dart!'.codeUnits);

      // FIX: Phase 4.4 — encrypt now validates handle and throws SibnaError
      // (invalidState) instead of UnimplementedError.
      expect(() async => await s1.encrypt(plaintext), throwsA(isA<SibnaError>()));
    });

    test('Session decrypt throws on uninitialized handle', () {
      final s2 = SibnaSession.fromSharedSecret(
        sharedSecret, 'local_b', 'remote_a'
      );

      final ct = Uint8List.fromList([0x01, 0x02]);

      // FIX: Phase 4.4 — decrypt now validates handle and throws SibnaError.
      expect(() async => await s2.decrypt(ct), throwsA(isA<SibnaError>()));
    });

    test('Session rejects empty plaintext', () async {
      final s1 = SibnaSession.fromSharedSecret(sharedSecret, 'a', 'b');
      
      expect(() => s1.encrypt(Uint8List(0)), throwsA(isA<ValidationError>()));
    });

    test('Session rejects empty ciphertext', () async {
      final s2 = SibnaSession.fromSharedSecret(sharedSecret, 'b', 'a');
      
      expect(() => s2.decrypt(Uint8List(0)), throwsA(isA<ValidationError>()));
    });

    test('Session stats verification', () {
      final s1 = SibnaSession.fromSharedSecret(sharedSecret, 'a', 'b');
      
      final stats = s1.stats;
      expect(stats['messagesSent'], equals(0));
      expect(stats['messagesReceived'], equals(0));
    });
  });
}