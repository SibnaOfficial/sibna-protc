import 'package:test/test.dart';
import 'package:sibna_protocol/sibna_protocol.dart';

void main() {
  group('Identity Tests', () {
    late SibnaContext context;

    setUpAll(() async {
      await SibnaProtocol.initialize();
      context = await SibnaContext.create();
    });

    tearDownAll(() async {
      context.dispose();
      SibnaProtocol.cleanup();
    });

    test('Identity generation produces valid keys', () async {
      final identity = await context.generateIdentity();
      expect(identity.publicKey.length, 32);
      expect(identity.privateKey, isNotNull);
    });

    test('Multiple identities are unique', () async {
      final id1 = await context.generateIdentity();
      final id2 = await context.generateIdentity();
      expect(id1.publicKey, isNot(equals(id2.publicKey)));
    });
  });
}