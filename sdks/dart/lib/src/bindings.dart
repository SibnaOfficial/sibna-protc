// ignore_for_file: non_constant_identifier_names

part of '../sibna_protocol.dart';

/// FFI bindings for the Sibna native library
class SibnaBindings {
  final DynamicLibrary _lib;

  SibnaBindings(this._lib);

  // Context functions
  late final _sibna_context_create_ptr = _lib.lookup<NativeFunction<Int32 Function(Pointer<Uint8>, Size, Pointer<Pointer<Void>>)>>(
    'sibna_context_create',
  );
  late final sibna_context_create = _sibna_context_create_ptr.asFunction<
    int Function(Pointer<Uint8>, int, Pointer<Pointer<Void>>)
  >();

  late final _sibna_context_destroy_ptr = _lib.lookup<NativeFunction<Void Function(Pointer<Void>)>>(
    'sibna_context_destroy',
  );
  late final sibna_context_destroy = _sibna_context_destroy_ptr.asFunction<
    void Function(Pointer<Void>)
  >();

  late final _sibna_context_set_device_link_ptr = _lib.lookup<
    NativeFunction<
      Int32 Function(
        Pointer<Void>,
        Uint32,
        Pointer<Uint8>,
        Pointer<Uint8>,
      )
    >
  >('sibna_context_set_device_link');
  late final sibna_context_set_device_link = _sibna_context_set_device_link_ptr.asFunction<
    int Function(Pointer<Void>, int, Pointer<Uint8>, Pointer<Uint8>)
  >();

  late final _sibna_version_ptr = _lib.lookup<NativeFunction<Int32 Function(Pointer<Char>, Size)>>(
    'sibna_version',
  );
  late final sibna_version = _sibna_version_ptr.asFunction<
    int Function(Pointer<Char>, int)
  >();

  // Encryption functions
  late final _sibna_encrypt_ptr = _lib.lookup<NativeFunction<
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<_ByteBuffer>,
    )
  >>('sibna_encrypt');
  late final sibna_encrypt = _sibna_encrypt_ptr.asFunction<
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<_ByteBuffer>,
    )
  >();

  late final _sibna_decrypt_ptr = _lib.lookup<NativeFunction<
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<_ByteBuffer>,
    )
  >>('sibna_decrypt');
  late final sibna_decrypt = _sibna_decrypt_ptr.asFunction<
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<_ByteBuffer>,
    )
  >();

  late final _sibna_generate_key_ptr = _lib.lookup<NativeFunction<Int32 Function(Pointer<Uint8>)>>(
    'sibna_generate_key',
  );
  late final sibna_generate_key = _sibna_generate_key_ptr.asFunction<
    int Function(Pointer<Uint8>)
  >();

  late final _sibna_random_bytes_ptr = _lib.lookup<NativeFunction<
    Int32 Function(Size, Pointer<Uint8>)
  >>('sibna_random_bytes');
  late final sibna_random_bytes = _sibna_random_bytes_ptr.asFunction<
    int Function(int, Pointer<Uint8>)
  >();

  late final _sibna_free_buffer_ptr = _lib.lookup<NativeFunction<Void Function(Pointer<_ByteBuffer>)>>(
    'sibna_free_buffer',
  );
  late final sibna_free_buffer = _sibna_free_buffer_ptr.asFunction<
    void Function(Pointer<_ByteBuffer>)
  >();

  // Session functions
  late final _sibna_session_create_ptr = _lib.lookup<NativeFunction<
    Int32 Function(
      Pointer<Void>,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Void>>,
    )
  >>('sibna_session_create');
  late final sibna_session_create = _sibna_session_create_ptr.asFunction<
    int Function(
      Pointer<Void>,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Void>>,
    )
  >();

  // FIX: Phase 4.3 — session_encrypt/decrypt were missing from Dart
  // bindings. These have 8 arguments matching the Rust core:
  // (context, session_id, session_id_len, plaintext/ciphertext,
  //  plaintext_len/ciphertext_len, associated_data, ad_len, out_buf).
  late final _sibna_session_encrypt_ptr = _lib.lookup<NativeFunction<
    Int32 Function(
      Pointer<Void>, Pointer<Uint8>, Size,
      Pointer<Uint8>, Size,
      Pointer<Uint8>, Size,
      Pointer<_ByteBuffer>,
    )
  >>('sibna_session_encrypt');
  late final sibna_session_encrypt = _sibna_session_encrypt_ptr.asFunction<
    int Function(
      Pointer<Void>, Pointer<Uint8>, int,
      Pointer<Uint8>, int,
      Pointer<Uint8>, int,
      Pointer<_ByteBuffer>,
    )
  >();

  late final _sibna_session_decrypt_ptr = _lib.lookup<NativeFunction<
    Int32 Function(
      Pointer<Void>, Pointer<Uint8>, Size,
      Pointer<Uint8>, Size,
      Pointer<Uint8>, Size,
      Pointer<_ByteBuffer>,
    )
  >>('sibna_session_decrypt');
  late final sibna_session_decrypt = _sibna_session_decrypt_ptr.asFunction<
    int Function(
      Pointer<Void>, Pointer<Uint8>, int,
      Pointer<Uint8>, int,
      Pointer<Uint8>, int,
      Pointer<_ByteBuffer>,
    )
  >();

  late final _sibna_session_destroy_ptr = _lib.lookup<NativeFunction<Void Function(Pointer<Void>)>>(
    'sibna_session_destroy',
  );
  late final sibna_session_destroy = _sibna_session_destroy_ptr.asFunction<
    void Function(Pointer<Void>)
  >();

  // FIX: Phase 4.3 — group session functions were missing.
  late final _sibna_group_create_ptr = _lib.lookup<NativeFunction<
    Int32 Function(Pointer<Uint8>, Size, Pointer<Pointer<Void>>)
  >>('sibna_group_create');
  late final sibna_group_create = _sibna_group_create_ptr.asFunction<
    int Function(Pointer<Uint8>, int, Pointer<Pointer<Void>>)
  >();

  late final _sibna_group_destroy_ptr = _lib.lookup<NativeFunction<Void Function(Pointer<Void>)>>(
    'sibna_group_destroy',
  );
  late final sibna_group_destroy = _sibna_group_destroy_ptr.asFunction<
    void Function(Pointer<Void>)
  >();

  // FIX: Phase 4.3 — identity generation was missing.
  late final _sibna_identity_generate_ptr = _lib.lookup<NativeFunction<
    Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Pointer<Void>>)
  >>('sibna_identity_generate');
  late final sibna_identity_generate = _sibna_identity_generate_ptr.asFunction<
    int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Pointer<Void>>)
  >();

  late final _sibna_identity_destroy_ptr = _lib.lookup<NativeFunction<Void Function(Pointer<Void>)>>(
    'sibna_identity_destroy',
  );
  late final sibna_identity_destroy = _sibna_identity_destroy_ptr.asFunction<
    void Function(Pointer<Void>)
  >();
}

/// Byte buffer structure matching the FFI
@Packed(1)
final class _ByteBuffer extends Struct {
  external Pointer<Uint8> data;
  @Size()
  external int len;
  @Size()
  external int capacity;
}

/// Error codes matching the native library
enum SibnaErrorCode {
  ok(0),
  invalidArgument(1),
  invalidKey(2),
  encryptionFailed(3),
  decryptionFailed(4),
  outOfMemory(5),
  invalidState(6),
  sessionNotFound(7),
  keyNotFound(8),
  rateLimitExceeded(9),
  internalError(10),
  bufferTooSmall(11),
  invalidCiphertext(12),
  authenticationFailed(13),
  libraryNotFound(100),
  notInitialized(101);

  final int code;
  const SibnaErrorCode(this.code);

  static SibnaErrorCode fromCode(int code) {
    return values.firstWhere(
      (e) => e.code == code,
      orElse: () => internalError,
    );
  }

  String get message {
    switch (this) {
      case ok:
        return 'Success';
      case invalidArgument:
        return 'Invalid argument';
      case invalidKey:
        return 'Invalid key';
      case encryptionFailed:
        return 'Encryption failed';
      case decryptionFailed:
        return 'Decryption failed';
      case outOfMemory:
        return 'Out of memory';
      case invalidState:
        return 'Invalid state';
      case sessionNotFound:
        return 'Session not found';
      case keyNotFound:
        return 'Key not found';
      case rateLimitExceeded:
        return 'Rate limit exceeded';
      case internalError:
        return 'Internal error';
      case bufferTooSmall:
        return 'Buffer too small';
      case invalidCiphertext:
        return 'Invalid ciphertext';
      case authenticationFailed:
        return 'Authentication failed';
      case libraryNotFound:
        return 'Native library not found';
      case notInitialized:
        return 'SDK not initialized';
    }
  }
}
