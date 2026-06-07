part of '../sibna_flutter.dart';
// ignore_for_file: non_constant_identifier_names, camel_case_types

// ─────────────────────────────────────────────────────────────
// ByteBuffer struct — mirrors the Rust FFI layout exactly
// ─────────────────────────────────────────────────────────────
@Packed(1)
final class _ByteBuffer extends Struct {
  external Pointer<Uint8> data;
  @Size()
  external int len;
  @Size()
  external int capacity;
}

// ─────────────────────────────────────────────────────────────
// All FFI bindings to libsibna
// ─────────────────────────────────────────────────────────────
class _SibnaBindings {
  final DynamicLibrary _lib;
  _SibnaBindings(this._lib);

  // ── Version ──────────────────────────────────────────────
  late final sibna_version = _lib
      .lookup<NativeFunction<Int32 Function(Pointer<Char>, Size)>>(
          'sibna_version')
      .asFunction<int Function(Pointer<Char>, int)>();

  // ── Context ──────────────────────────────────────────────
  late final sibna_context_create = _lib
      .lookup<NativeFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Pointer<Void>>)>>(
          'sibna_context_create')
      .asFunction<int Function(Pointer<Uint8>, int, Pointer<Pointer<Void>>)>();

  late final sibna_context_destroy = _lib
      .lookup<NativeFunction<Void Function(Pointer<Void>)>>(
          'sibna_context_destroy')
      .asFunction<void Function(Pointer<Void>)>();

  // ── Session ──────────────────────────────────────────────
  late final sibna_session_create = _lib
      .lookup<NativeFunction<
          Int32 Function(
              Pointer<Void>, Pointer<Uint8>, Size, Pointer<Pointer<Void>>)>>(
          'sibna_session_create')
      .asFunction<
          int Function(
              Pointer<Void>, Pointer<Uint8>, int, Pointer<Pointer<Void>>)>();

  late final sibna_session_destroy = _lib
      .lookup<NativeFunction<Void Function(Pointer<Void>)>>(
          'sibna_session_destroy')
      .asFunction<void Function(Pointer<Void>)>();

  // ── Crypto: encrypt / decrypt ─────────────────────────────
  late final sibna_encrypt = _lib
      .lookup<NativeFunction<
          Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>,
              Size, Pointer<_ByteBuffer>)>>('sibna_encrypt')
      .asFunction<
          int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>,
              int, Pointer<_ByteBuffer>)>();

  late final sibna_decrypt = _lib
      .lookup<NativeFunction<
          Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>,
              Size, Pointer<_ByteBuffer>)>>('sibna_decrypt')
      .asFunction<
          int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>,
              int, Pointer<_ByteBuffer>)>();

  // ── Key / Random ─────────────────────────────────────────
  late final sibna_generate_key = _lib
      .lookup<NativeFunction<Int32 Function(Pointer<Uint8>)>>(
          'sibna_generate_key')
      .asFunction<int Function(Pointer<Uint8>)>();

  late final sibna_random_bytes = _lib
      .lookup<NativeFunction<Int32 Function(Size, Pointer<Uint8>)>>(
          'sibna_random_bytes')
      .asFunction<int Function(int, Pointer<Uint8>)>();

  // ── Buffer management ────────────────────────────────────
  late final sibna_free_buffer = _lib
      .lookup<NativeFunction<Void Function(Pointer<_ByteBuffer>)>>(
          'sibna_free_buffer')
      .asFunction<void Function(Pointer<_ByteBuffer>)>();

  // ── Session encrypt / decrypt (Double Ratchet) ────────────
  // FIX: These were missing — session.dart silently used a random ephemeral
  // key per message that the recipient could never decrypt.
  // Rust core must export sibna_session_encrypt / sibna_session_decrypt.
  // FIX: Phase 4.1 — the previous binding declared a 6-argument signature
  // (context, session_id, session_id_len, plaintext, plaintext_len,
  // ciphertext_out). The native Rust function
  // core::ffi::sibna_session_encrypt actually has 8 arguments: the two
  // AEAD-associated-data arguments (associated_data, ad_len) come between
  // plaintext_len and ciphertext_out, and any caller passing a non-null
  // associated_data buffer would corrupt the stack and crash the host
  // process. The new binding matches the native ABI exactly.
  late final sibna_session_encrypt = _lib
      .lookup<NativeFunction<
          Int32 Function(Pointer<Void>, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<_ByteBuffer>)>>('sibna_session_encrypt')
      .asFunction<
          int Function(Pointer<Void>, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<_ByteBuffer>)>();

  late final sibna_session_decrypt = _lib
      .lookup<NativeFunction<
          Int32 Function(Pointer<Void>, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<_ByteBuffer>)>>('sibna_session_decrypt')
      .asFunction<
          int Function(Pointer<Void>, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<_ByteBuffer>)>();

  // ── Group session ─────────────────────────────────────────
  // FIX: sibna_group_create was missing — group.dart threw UnimplementedError.
  late final sibna_group_create = _lib
      .lookup<NativeFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Pointer<Void>>)>>(
          'sibna_group_create')
      .asFunction<int Function(Pointer<Uint8>, int, Pointer<Pointer<Void>>)>();

  late final sibna_group_destroy = _lib
      .lookup<NativeFunction<Void Function(Pointer<Void>)>>('sibna_group_destroy')
      .asFunction<void Function(Pointer<Void>)>();

  // ── Identity: generate and verify ────────────────────────
  // FIX: Both were missing — context.dart and identity.dart stubs could not
  // generate real keys or verify signatures.
  late final sibna_identity_generate = _lib
      .lookup<NativeFunction<
          Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Pointer<Void>>)>>(
          'sibna_identity_generate')
      .asFunction<int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Pointer<Void>>)>();

  late final sibna_identity_verify = _lib
      .lookup<NativeFunction<
          Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>)>>(
          'sibna_identity_verify')
      .asFunction<int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>)>();

  late final sibna_identity_destroy = _lib
      .lookup<NativeFunction<Void Function(Pointer<Void>)>>('sibna_identity_destroy')
      .asFunction<void Function(Pointer<Void>)>();
}
