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
}
