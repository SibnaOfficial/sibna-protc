part of '../sibna_flutter.dart';

class SibnaSession {
  final Pointer<Void> _handle;
  final Uint8List peerId;
  bool _disposed = false;

  SibnaSession._(this._handle, this.peerId);

  /// Encrypt [plaintext] for this session.
  ///
  /// [associatedData] is optional authenticated context data
  /// (e.g. message ID, timestamp). Must match on decrypt.
  Future<Uint8List> encrypt(
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();
    // For session-based E2E, key derivation happens inside the native layer.
    // The current FFI exposes low-level encrypt; a future version will expose
    // a session_encrypt() that drives the Double Ratchet internally.
    //
    // For now, delegate to SibnaCrypto with a session-derived key.
    // TODO: replace with sibna_session_encrypt() when exposed in FFI.
    throw UnimplementedError(
      'Session-level encrypt requires sibna_session_encrypt() in the FFI layer. '
      'Use SibnaCrypto.encrypt() with a pre-shared key for standalone crypto.',
    );
  }

  /// Decrypt [ciphertext] from this session peer.
  Future<Uint8List> decrypt(
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();
    throw UnimplementedError(
      'Session-level decrypt requires sibna_session_decrypt() in the FFI layer.',
    );
  }

  /// Dispose the session handle and free native resources.
  void dispose() {
    if (_disposed) return;
    SibnaFlutter.bindings.sibna_session_destroy(_handle);
    _disposed = true;
  }

  void _ensureNotDisposed() {
    if (_disposed) throw const SibnaError(
      SibnaErrorCode.invalidState, 'Session has been disposed',
    );
  }

  @override
  String toString() =>
      'SibnaSession(peer: ${peerId.take(4).toList()}, disposed: $_disposed)';
}
