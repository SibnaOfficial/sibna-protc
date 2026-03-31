part of '../sibna_flutter.dart';

class SibnaCrypto {
  SibnaCrypto._();

  /// Generate a cryptographically secure random 32-byte key.
  static Uint8List generateKey() {
    final ptr = calloc<Uint8>(keyLength);
    try {
      _checkResult(
        SibnaFlutter.bindings.sibna_generate_key(ptr),
        op: 'generateKey',
      );
      return Uint8List.fromList(ptr.asTypedList(keyLength));
    } finally {
      // Zero the native buffer before freeing
      for (var i = 0; i < keyLength; i++) ptr[i] = 0;
      calloc.free(ptr);
    }
  }

  /// Generate [length] cryptographically secure random bytes.
  static Uint8List randomBytes(int length) {
    if (length <= 0 || length > 1024 * 1024) {
      throw SibnaValidationError('length', 'length must be 1–1048576');
    }
    final ptr = calloc<Uint8>(length);
    try {
      _checkResult(
        SibnaFlutter.bindings.sibna_random_bytes(length, ptr),
        op: 'randomBytes',
      );
      return Uint8List.fromList(ptr.asTypedList(length));
    } finally {
      calloc.free(ptr);
    }
  }

  /// Encrypt [plaintext] with [key] (ChaCha20-Poly1305).
  ///
  /// [key] must be exactly 32 bytes.
  /// [associatedData] is optional authenticated (but unencrypted) data.
  ///
  /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
  static Uint8List encrypt(
    Uint8List key,
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) {
    _validateKey(key);
    _validateMessage(plaintext);

    final keyPtr   = _copyToNative(key);
    final ptPtr    = _copyToNative(plaintext);
    final adPtr    = associatedData != null ? _copyToNative(associatedData) : nullptr;
    final ctBuf    = calloc<_ByteBuffer>();

    try {
      _checkResult(
        SibnaFlutter.bindings.sibna_encrypt(
          keyPtr, ptPtr, plaintext.length,
          adPtr, associatedData?.length ?? 0,
          ctBuf,
        ),
        op: 'encrypt',
      );
      return _readAndFreeBuffer(ctBuf);
    } finally {
      // Zero sensitive input memory before freeing
      for (var i = 0; i < keyLength; i++) keyPtr[i] = 0;
      calloc.free(keyPtr);
      calloc.free(ptPtr);
      if (adPtr != nullptr) calloc.free(adPtr);
      calloc.free(ctBuf);
    }
  }

  /// Decrypt [ciphertext] with [key] (ChaCha20-Poly1305).
  ///
  /// Throws [SibnaError] with [SibnaErrorCode.authenticationFailed]
  /// if the ciphertext was tampered with or the key is wrong.
  static Uint8List decrypt(
    Uint8List key,
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) {
    _validateKey(key);
    if (ciphertext.length < 29) {
      throw SibnaValidationError('ciphertext', 'ciphertext too short');
    }

    final keyPtr   = _copyToNative(key);
    final ctPtr    = _copyToNative(ciphertext);
    final adPtr    = associatedData != null ? _copyToNative(associatedData) : nullptr;
    final ptBuf    = calloc<_ByteBuffer>();

    try {
      _checkResult(
        SibnaFlutter.bindings.sibna_decrypt(
          keyPtr, ctPtr, ciphertext.length,
          adPtr, associatedData?.length ?? 0,
          ptBuf,
        ),
        op: 'decrypt',
      );
      return _readAndFreeBuffer(ptBuf);
    } finally {
      for (var i = 0; i < keyLength; i++) keyPtr[i] = 0;
      calloc.free(keyPtr);
      calloc.free(ctPtr);
      if (adPtr != nullptr) calloc.free(adPtr);
      calloc.free(ptBuf);
    }
  }

  // ── Validation helpers ──────────────────────────────────
  static void _validateKey(Uint8List key) {
    if (key.length != keyLength) {
      throw SibnaValidationError('key', 'Key must be $keyLength bytes');
    }
    if (key.every((b) => b == 0)) {
      throw SibnaValidationError('key', 'Key must not be all zeros');
    }
  }

  static void _validateMessage(Uint8List msg) {
    if (msg.isEmpty) {
      throw SibnaValidationError('plaintext', 'Message must not be empty');
    }
    if (msg.length > maxMessageSize) {
      throw SibnaValidationError(
          'plaintext', 'Message exceeds maximum size ($maxMessageSize bytes)');
    }
  }
}
