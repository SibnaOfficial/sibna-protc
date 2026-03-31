part of '../sibna_protocol.dart';

/// Standalone cryptographic operations
class SibnaCrypto {
  /// Private constructor to prevent instantiation
  SibnaCrypto._();

  /// Generate a random 32-byte encryption key
  static Uint8List generateKey() {
    _ensureInitialized();

    final keyPtr = calloc<Uint8>(keyLength);
    try {
      final result = _bindings.sibna_generate_key(keyPtr);
      checkResult(result, operation: 'generateKey');

      return Uint8List.fromList(
        keyPtr.asTypedList(keyLength),
      );
    } finally {
      calloc.free(keyPtr);
    }
  }

  /// Generate random bytes
  static Uint8List randomBytes(int length) {
    _ensureInitialized();

    final bufferPtr = calloc<Uint8>(length);
    try {
      final result = _bindings.sibna_random_bytes(length, bufferPtr);
      checkResult(result, operation: 'randomBytes');

      return Uint8List.fromList(
        bufferPtr.asTypedList(length),
      );
    } finally {
      calloc.free(bufferPtr);
    }
  }

  /// Encrypt data with a key
  ///
  /// [key] must be 32 bytes
  /// [plaintext] is the data to encrypt
  /// [associatedData] is optional additional authenticated data
  static Uint8List encrypt(
    Uint8List key,
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) {
    _ensureInitialized();

    // Validate inputs
    SibnaUtils.validateKeyLength(key);
    SibnaUtils.validateMessageSize(plaintext);

    final keyPtr = calloc<Uint8>(keyLength);
    final plaintextPtr = calloc<Uint8>(plaintext.length);
    final adPtr = associatedData != null ? calloc<Uint8>(associatedData.length) : nullptr;
    final ciphertextBuffer = calloc<_ByteBuffer>();

    try {
      // Copy data to native memory
      keyPtr.asTypedList(keyLength).setAll(0, key);
      plaintextPtr.asTypedList(plaintext.length).setAll(0, plaintext);
      if (associatedData != null) {
        adPtr!.asTypedList(associatedData.length).setAll(0, associatedData);
      }

      // Encrypt
      final result = _bindings.sibna_encrypt(
        keyPtr,
        plaintextPtr,
        plaintext.length,
        adPtr,
        associatedData?.length ?? 0,
        ciphertextBuffer,
      );
      checkResult(result, operation: 'encrypt');

      // Copy result
      final ciphertext = Uint8List.fromList(
        ciphertextBuffer.ref.data.asTypedList(ciphertextBuffer.ref.len),
      );

      // Free native buffer
      _bindings.sibna_free_buffer(ciphertextBuffer);

      return ciphertext;
    } finally {
      calloc.free(keyPtr);
      calloc.free(plaintextPtr);
      if (adPtr != nullptr) calloc.free(adPtr);
      calloc.free(ciphertextBuffer);
    }
  }

  /// Decrypt data with a key
  ///
  /// [key] must be 32 bytes
  /// [ciphertext] is the data to decrypt
  /// [associatedData] must match the data used during encryption
  static Uint8List decrypt(
    Uint8List key,
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) {
    _ensureInitialized();

    // Validate inputs
    SibnaUtils.validateKeyLength(key);
    if (ciphertext.isEmpty) {
      throw ValidationError(
        SibnaErrorCode.invalidCiphertext,
        'Ciphertext cannot be empty',
        field: 'ciphertext',
      );
    }

    final keyPtr = calloc<Uint8>(keyLength);
    final ciphertextPtr = calloc<Uint8>(ciphertext.length);
    final adPtr = associatedData != null ? calloc<Uint8>(associatedData.length) : nullptr;
    final plaintextBuffer = calloc<_ByteBuffer>();

    try {
      // Copy data to native memory
      keyPtr.asTypedList(keyLength).setAll(0, key);
      ciphertextPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);
      if (associatedData != null) {
        adPtr!.asTypedList(associatedData.length).setAll(0, associatedData);
      }

      // Decrypt
      final result = _bindings.sibna_decrypt(
        keyPtr,
        ciphertextPtr,
        ciphertext.length,
        adPtr,
        associatedData?.length ?? 0,
        plaintextBuffer,
      );
      checkResult(result, operation: 'decrypt');

      // Copy result
      final plaintext = Uint8List.fromList(
        plaintextBuffer.ref.data.asTypedList(plaintextBuffer.ref.len),
      );

      // Free native buffer
      _bindings.sibna_free_buffer(plaintextBuffer);

      return plaintext;
    } finally {
      calloc.free(keyPtr);
      calloc.free(ciphertextPtr);
      if (adPtr != nullptr) calloc.free(adPtr);
      calloc.free(plaintextBuffer);
    }
  }

  /// Derive a key using HKDF
  ///
  /// [ikm] is the input keying material
  /// [salt] is optional salt
  /// [info] is optional context information
  /// [length] is the desired output length (default 32)
  static Uint8List hkdf(
    Uint8List ikm, {
    Uint8List? salt,
    Uint8List? info,
    int length = keyLength,
  }) {
    // Use the crypto package's HKDF
    final hmac = Hmac(sha256, salt ?? Uint8List(0));
    final prk = hmac.convert(ikm);

    final result = <int>[];
    var counter = 0;
    var previous = <int>[];

    while (result.length < length) {
      counter++;
      final hmac2 = Hmac(sha256, prk.bytes);
      final data = [...previous, ...(info ?? []), counter];
      final okm = hmac2.convert(data);
      result.addAll(okm.bytes);
      previous = okm.bytes;
    }

    return Uint8List.fromList(result.sublist(0, length));
  }

  /// Hash data using SHA-256
  static Uint8List sha256Hash(Uint8List data) {
    final hash = sha256.convert(data);
    return Uint8List.fromList(hash.bytes);
  }

  /// Hash data using SHA-512
  static Uint8List sha512Hash(Uint8List data) {
    final hash = sha512.convert(data);
    return Uint8List.fromList(hash.bytes);
  }

  /// Calculate HMAC-SHA256
  static Uint8List hmacSha256(Uint8List key, Uint8List data) {
    final hmac = Hmac(sha256, key);
    final result = hmac.convert(data);
    return Uint8List.fromList(result.bytes);
  }

  /// Ensure SDK is initialized
  static void _ensureInitialized() {
    if (!SibnaProtocol.isInitialized) {
      throw SibnaError(
        SibnaErrorCode.notInitialized,
        'SDK not initialized. Call SibnaProtocol.initialize() first.',
      );
    }
  }
}

/// AES-GCM encryption (Dart implementation for platforms without native library)
class AesGcm {
  /// Encrypt using AES-256-GCM
  /// Note: This is a placeholder - use native library for production
  static Uint8List encrypt(Uint8List key, Uint8List plaintext, Uint8List nonce) {
    throw UnimplementedError('Use native library for AES-GCM encryption');
  }

  /// Decrypt using AES-256-GCM
  /// Note: This is a placeholder - use native library for production
  static Uint8List decrypt(Uint8List key, Uint8List ciphertext, Uint8List nonce) {
    throw UnimplementedError('Use native library for AES-GCM decryption');
  }
}

/// ChaCha20-Poly1305 encryption
class ChaCha20Poly1305 {
  /// Encrypt using ChaCha20-Poly1305
  /// Note: This delegates to the native library
  static Uint8List encrypt(
    Uint8List key,
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) {
    return SibnaCrypto.encrypt(key, plaintext, associatedData: associatedData);
  }

  /// Decrypt using ChaCha20-Poly1305
  /// Note: This delegates to the native library
  static Uint8List decrypt(
    Uint8List key,
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) {
    return SibnaCrypto.decrypt(key, ciphertext, associatedData: associatedData);
  }
}
