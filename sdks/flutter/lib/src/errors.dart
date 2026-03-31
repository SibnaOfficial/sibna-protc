part of '../sibna_flutter.dart';

/// Error codes mirroring the Rust FFI
enum SibnaErrorCode {
  ok(0), invalidArgument(1), invalidKey(2), encryptionFailed(3),
  decryptionFailed(4), outOfMemory(5), invalidState(6), sessionNotFound(7),
  keyNotFound(8), rateLimitExceeded(9), internalError(10), bufferTooSmall(11),
  invalidCiphertext(12), authenticationFailed(13), libraryNotFound(100),
  notInitialized(101);

  final int code;
  const SibnaErrorCode(this.code);

  static SibnaErrorCode fromCode(int code) =>
      values.firstWhere((e) => e.code == code, orElse: () => internalError);

  String get message => switch (this) {
    ok                  => 'Success',
    invalidArgument     => 'Invalid argument',
    invalidKey          => 'Invalid or weak key',
    encryptionFailed    => 'Encryption failed',
    decryptionFailed    => 'Decryption failed',
    outOfMemory         => 'Out of memory',
    invalidState        => 'Invalid protocol state',
    sessionNotFound     => 'Session not found',
    keyNotFound         => 'Key not found',
    rateLimitExceeded   => 'Rate limit exceeded',
    internalError       => 'Internal error',
    bufferTooSmall      => 'Output buffer too small',
    invalidCiphertext   => 'Invalid or corrupted ciphertext',
    authenticationFailed => 'Authentication / AEAD tag mismatch',
    libraryNotFound     => 'Native library not found',
    notInitialized      => 'Call SibnaFlutter.initialize() first',
  };
}

class SibnaError implements Exception {
  final SibnaErrorCode code;
  final String message;
  const SibnaError(this.code, this.message);
  @override String toString() => 'SibnaError(${code.name}): $message';
}

class SibnaNotInitializedError extends SibnaError {
  const SibnaNotInitializedError()
      : super(SibnaErrorCode.notInitialized,
            'SibnaFlutter.initialize() has not been called.');
}

class SibnaPluginError implements Exception {
  final String message;
  const SibnaPluginError(this.message);
  @override String toString() => 'SibnaPluginError: $message';
}

class SibnaValidationError extends SibnaError {
  final String field;
  const SibnaValidationError(this.field, String message)
      : super(SibnaErrorCode.invalidArgument, message);
  @override String toString() => 'SibnaValidationError($field): $message';
}
