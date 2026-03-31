/// Sibna Flutter Plugin — v1.0.0
///
/// Flutter plugin for Sibna Protocol — Signal Protocol E2EE.
/// Uses dart:ffi to call the Rust core on all platforms.
///
/// ## Quick start
/// ```dart
/// import 'package:sibna_flutter/sibna_flutter.dart';
///
/// void main() async {
///   WidgetsFlutterBinding.ensureInitialized();
///   await SibnaFlutter.initialize();
///   runApp(MyApp());
/// }
/// ```
library sibna_flutter;

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as path;
import 'package:path_provider/path_provider.dart';
import 'package:crypto/crypto.dart';

// All src files are parts of this library.
// This gives them access to all private types (_ByteBuffer, etc.)
part 'src/ffi_bindings.dart';
part 'src/sibna_flutter_base.dart';
part 'src/errors.dart';
part 'src/crypto.dart';
part 'src/context.dart';
part 'src/session.dart';
part 'src/identity.dart';
part 'src/safety_number.dart';
part 'src/group.dart';
