part of '../sibna_flutter.dart';

class SibnaContext {
  final Pointer<Void> _handle;
  bool _disposed = false;

  SibnaContext._(this._handle);

  /// Create a new context. [password] is the master password
  /// for local key storage — must contain upper + lower + digit, ≥8 chars.
  static Future<SibnaContext> create({String? password}) async {
    final ctxPtr = calloc<Pointer<Void>>();

    Pointer<Uint8>? pwPtr;
    try {
      int pwLen = 0;
      if (password != null) {
        final pwBytes = password.codeUnits;
        pwPtr = calloc<Uint8>(pwBytes.length);
        pwPtr.asTypedList(pwBytes.length).setAll(0, pwBytes);
        pwLen = pwBytes.length;
      }

      final rc = SibnaFlutter.bindings.sibna_context_create(
        pwPtr ?? nullptr,
        pwLen,
        ctxPtr,
      );
      _checkResult(rc, op: 'contextCreate');

      return SibnaContext._(ctxPtr.value);
    } finally {
      if (pwPtr != null) {
        // Zero password in native memory
        for (var i = 0; i < (password?.length ?? 0); i++) pwPtr[i] = 0;
        calloc.free(pwPtr);
      }
      calloc.free(ctxPtr);
    }
  }

  /// Create a session with [peerId].
  ///
  /// [peerId] is a unique identifier for the remote peer (e.g. user ID bytes).
  Future<SibnaSession> createSession(Uint8List peerId) async {
    _ensureNotDisposed();
    if (peerId.isEmpty) {
      throw SibnaValidationError('peerId', 'Peer ID must not be empty');
    }

    final peerPtr    = _copyToNative(peerId);
    final sessionPtr = calloc<Pointer<Void>>();
    try {
      _checkResult(
        SibnaFlutter.bindings.sibna_session_create(
          _handle, peerPtr, peerId.length, sessionPtr,
        ),
        op: 'sessionCreate',
      );
      return SibnaSession._(sessionPtr.value, peerId);
    } finally {
      calloc.free(peerPtr);
      calloc.free(sessionPtr);
    }
  }

  /// Dispose this context and zero all keys in native memory.
  void dispose() {
    if (_disposed) return;
    SibnaFlutter.bindings.sibna_context_destroy(_handle);
    _disposed = true;
  }

  void _ensureNotDisposed() {
    if (_disposed) throw const SibnaError(
      SibnaErrorCode.invalidState, 'Context has been disposed',
    );
  }

  @override
  String toString() => 'SibnaContext(disposed: $_disposed)';
}
