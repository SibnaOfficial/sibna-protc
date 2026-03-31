part of '../sibna_protocol.dart';

/// Exception thrown when a Sibna operation fails
class SibnaError implements Exception {
  /// Error code
  final SibnaErrorCode code;

  /// Error message
  final String message;

  /// Optional stack trace
  final StackTrace? stackTrace;

  /// Create a new Sibna error
  SibnaError(this.code, this.message, {this.stackTrace});

  /// Create from error code
  factory SibnaError.fromCode(int code, {StackTrace? stackTrace}) {
    final errorCode = SibnaErrorCode.fromCode(code);
    return SibnaError(errorCode, errorCode.message, stackTrace: stackTrace);
  }

  @override
  String toString() => 'SibnaError[$code]: $message';

  /// Check if this is a security-related error
  bool get isSecurityError =>
    code == SibnaErrorCode.invalidKey ||
    code == SibnaErrorCode.authenticationFailed ||
    code == SibnaErrorCode.invalidCiphertext;

  /// Check if this is a recoverable error
  bool get isRecoverable =>
    code == SibnaErrorCode.rateLimitExceeded ||
    code == SibnaErrorCode.bufferTooSmall;

  /// Check if this is a fatal error
  bool get isFatal =>
    code == SibnaErrorCode.outOfMemory ||
    code == SibnaErrorCode.internalError;
}

/// Exception for validation errors
class ValidationError extends SibnaError {
  /// Field that failed validation
  final String? field;

  ValidationError(
    SibnaErrorCode code,
    String message, {
    this.field,
    StackTrace? stackTrace,
  }) : super(code, message, stackTrace: stackTrace);

  @override
  String toString() {
    if (field != null) {
      return 'ValidationError[$field]: $message';
    }
    return 'ValidationError: $message';
  }
}

/// Exception for cryptographic errors
class CryptoError extends SibnaError {
  CryptoError(SibnaErrorCode code, String message, {StackTrace? stackTrace})
    : super(code, message, stackTrace: stackTrace);
}

/// Exception for session errors
class SessionError extends SibnaError {
  SessionError(SibnaErrorCode code, String message, {StackTrace? stackTrace})
    : super(code, message, stackTrace: stackTrace);
}

/// Exception for group messaging errors
class GroupError extends SibnaError {
  GroupError(SibnaErrorCode code, String message, {StackTrace? stackTrace})
    : super(code, message, stackTrace: stackTrace);
}

/// Helper function to check result and throw if error
void checkResult(int result, {String? operation, StackTrace? stackTrace}) {
  if (result == SibnaErrorCode.ok.code) return;

  final code = SibnaErrorCode.fromCode(result);
  final message = operation != null
    ? '$operation failed: ${code.message}'
    : code.message;

  throw SibnaError(code, message, stackTrace: stackTrace);
}
