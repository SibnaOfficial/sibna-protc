import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:sibna_flutter/sibna_flutter.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize the Sibna native library once at startup
  await SibnaFlutter.initialize();

  runApp(const SibnaExampleApp());
}

class SibnaExampleApp extends StatelessWidget {
  const SibnaExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Sibna Protocol Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const DemoPage(),
    );
  }
}

class DemoPage extends StatefulWidget {
  const DemoPage({super.key});

  @override
  State<DemoPage> createState() => _DemoPageState();
}

class _DemoPageState extends State<DemoPage> {
  String _output = 'Press a button to test the protocol.';
  bool _loading = false;

  Future<void> _runDemo() async {
    setState(() { _loading = true; _output = 'Running...'; });
    final sb = StringBuffer();

    try {
      // 1. Generate a key
      final key = SibnaCrypto.generateKey();
      sb.writeln('Key generated: ${key.length} bytes');

      // 2. Encrypt a message
      final plaintext = Uint8List.fromList('Hello from Flutter!'.codeUnits);
      final ciphertext = SibnaCrypto.encrypt(
        key, plaintext,
        associatedData: Uint8List.fromList('demo-ad'.codeUnits),
      );
      sb.writeln('Encrypted: ${ciphertext.length} bytes');

      // 3. Decrypt
      final decrypted = SibnaCrypto.decrypt(
        key, ciphertext,
        associatedData: Uint8List.fromList('demo-ad'.codeUnits),
      );
      final text = String.fromCharCodes(decrypted);
      sb.writeln('Decrypted: $text');

      // 4. Safety number
      final k1 = SibnaCrypto.randomBytes(32);
      final k2 = SibnaCrypto.randomBytes(32);
      final sn = SibnaSafetyNumber.calculate(k1, k2);
      sb.writeln('Safety number:\n${sn.formatted}');

      sb.writeln('\nAll operations succeeded!');
    } catch (e) {
      sb.writeln('Error: $e');
    }

    setState(() { _output = sb.toString(); _loading = false; });
  }

  Future<void> _testTamper() async {
    setState(() { _loading = true; _output = 'Testing tamper detection...'; });
    try {
      final key = SibnaCrypto.generateKey();
      final ct = SibnaCrypto.encrypt(
        key, Uint8List.fromList('secret'.codeUnits),
      );
      // Flip a byte
      ct[ct.length ~/ 2] ^= 0xFF;
      SibnaCrypto.decrypt(key, ct);
      setState(() { _output = 'ERROR: tamper was not detected!'; _loading = false; });
    } on SibnaError catch (e) {
      setState(() {
        _output = 'Tamper correctly detected: ${e.code.message}';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Sibna Protocol v9'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Text(
                  'Native version: ${SibnaFlutter.nativeVersion}',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            ),
            const SizedBox(height: 12),
            ElevatedButton(
              onPressed: _loading ? null : _runDemo,
              child: const Text('Run encryption demo'),
            ),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: _loading ? null : _testTamper,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.orange,
                foregroundColor: Colors.white,
              ),
              child: const Text('Test tamper detection'),
            ),
            const SizedBox(height: 16),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.black87,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SingleChildScrollView(
                  child: SelectableText(
                    _output,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      color: Colors.greenAccent,
                      fontSize: 13,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
