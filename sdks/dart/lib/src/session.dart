part of '../sibna_protocol.dart';

/// Secure session for encrypted communication
class SibnaSession {
  // FIX: Phase 4.4 — the session now also keeps a strong reference to
  // the parent context. ``sibna_session_encrypt`` and
  // ``sibna_session_decrypt`` both take ``*mut SibnaContext`` as their
  // first argument (the SecureContext that owns the session table),
  // not the session handle itself. The previous code passed the
  // session handle as the context pointer, which on every call would
  // either be misinterpreted as a different ``SecureContext`` (UB) or
  // crash the host process.
  final Pointer<Void> _context;
  Pointer<Void> _handle;
  final Uint8List _peerId;
  bool _disposed = false;
  int _messagesSent = 0;
  int _messagesReceived = 0;
  DateTime? _establishedAt;

  /// Get the peer ID
  Uint8List get peerId => Uint8List.fromList(_peerId);

  /// Get the number of messages sent
  int get messagesSent => _messagesSent;

  /// Get the number of messages received
  int get messagesReceived => _messagesReceived;

  /// Get the session establishment time
  DateTime? get establishedAt => _establishedAt;

  /// Check if the session is disposed
  bool get isDisposed => _disposed;

  /// Create a session from an existing shared secret (used for restoration/testing)
  factory SibnaSession.fromSharedSecret(
    Uint8List sharedSecret,
    String localDh,
    String remoteDh,
  ) {
    // In a real implementation, this would call a native function
    // that initializes the DoubleRatchet state directly from the secret.
    // For now, we simulate the handle creation.
    return SibnaSession._(nullptr, nullptr, Uint8List.fromList(utf8.encode(remoteDh)));
  }

  /// Private constructor
  SibnaSession._(this._context, this._handle, this._peerId) {
    _establishedAt = DateTime.now();
  }


  /// Perform X3DH handshake
  ///
  /// [peerBundle] is the peer's prekey bundle
  /// [initiator] is true if we are the initiator
  Future<void> performHandshake(
    PreKeyBundle peerBundle, {
    required bool initiator,
  }) async {
    _ensureNotDisposed();

    if (peerBundle.isExpired) {
      throw SibnaError(
        SibnaErrorCode.invalidState,
        'Peer prekey bundle has expired',
      );
    }

    // This would call the native library in production
    // For now, just mark as established
    _establishedAt = DateTime.now();
  }

  /// Encrypt a message
  ///
  /// [plaintext] is the message to encrypt
  /// [associatedData] is optional additional authenticated data
  Future<Uint8List> encrypt(
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();

    if (plaintext.isEmpty) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Plaintext cannot be empty',
        field: 'plaintext',
      );
    }

    if (plaintext.length > maxMessageSize) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Message too large: ${plaintext.length} > $maxMessageSize',
        field: 'plaintext',
      );
    }

    if (_handle == nullptr) {
      throw SibnaError(
        SibnaErrorCode.invalidState,
        'Session not initialised — call SibnaContext.createSession() first.',
      );
    }

    final plaintextPtr = _copyToNative(plaintext);
    final adPtr = associatedData != null ? _copyToNative(associatedData) : nullptr;
    final peerIdPtr = _copyToNative(_peerId);
    final outBuf = calloc<_ByteBuffer>();

    try {
      final rc = _bindings.sibna_session_encrypt(
        _context, peerIdPtr, _peerId.length,
        plaintextPtr, plaintext.length,
        adPtr, associatedData?.length ?? 0, outBuf,
      );
      if (rc != SibnaErrorCode.ok.code) {
        throw SibnaError(SibnaErrorCode.fromCode(rc), 'session_encrypt failed');
      }
      final result = _readAndFreeBuffer(outBuf);
      _messagesSent++;
      return result;
    } finally {
      calloc.free(plaintextPtr);
      calloc.free(peerIdPtr);
      if (adPtr != nullptr) calloc.free(adPtr);
      calloc.free(outBuf);
    }
  }

  /// Decrypt a message
  ///
  /// [ciphertext] is the message to decrypt
  /// [associatedData] must match the data used during encryption
  Future<Uint8List> decrypt(
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();

    if (ciphertext.isEmpty) {
      throw ValidationError(
        SibnaErrorCode.invalidCiphertext,
        'Ciphertext cannot be empty',
        field: 'ciphertext',
      );
    }

    if (_handle == nullptr) {
      throw SibnaError(
        SibnaErrorCode.invalidState,
        'Session not initialised',
      );
    }

    final ctPtr = _copyToNative(ciphertext);
    final adPtr = associatedData != null ? _copyToNative(associatedData) : nullptr;
    final peerIdPtr = _copyToNative(_peerId);
    final outBuf = calloc<_ByteBuffer>();

    try {
      final rc = _bindings.sibna_session_decrypt(
        _context, peerIdPtr, _peerId.length,
        ctPtr, ciphertext.length,
        adPtr, associatedData?.length ?? 0, outBuf,
      );
      if (rc != SibnaErrorCode.ok.code) {
        throw SibnaError(SibnaErrorCode.fromCode(rc), 'session_decrypt failed');
      }
      final result = _readAndFreeBuffer(outBuf);
      _messagesReceived++;
      return result;
    } finally {
      calloc.free(ctPtr);
      calloc.free(peerIdPtr);
      if (adPtr != nullptr) calloc.free(adPtr);
      calloc.free(outBuf);
    }
  }

  /// Get the current message number
  int get currentMessageNumber => _messagesSent + _messagesReceived;

  /// Check if the session is established
  bool get isEstablished => _establishedAt != null;

  /// Get session age
  Duration? get age {
    if (_establishedAt == null) return null;
    return DateTime.now().difference(_establishedAt!);
  }

  /// Get session statistics
  Map<String, dynamic> get stats => {
    'peerId': _peerId.toHex(),
    'messagesSent': _messagesSent,
    'messagesReceived': _messagesReceived,
    'establishedAt': _establishedAt?.toIso8601String(),
    'age': age?.inSeconds,
    'isEstablished': isEstablished,
  };

  /// Dispose the session and free resources
  void dispose() {
    if (_disposed) return;

    if (_handle != nullptr) {
      _bindings.sibna_session_destroy(_handle);
      _handle = nullptr;
    }

    // Securely clear peer ID
    _peerId.secureClear();

    _disposed = true;
  }

  // Helper: copy a Dart Uint8List to native memory via calloc
  static Pointer<Uint8> _copyToNative(Uint8List data) {
    final ptr = calloc<Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }

  // Helper: read a _ByteBuffer result and free it
  static Uint8List _readAndFreeBuffer(Pointer<_ByteBuffer> bufPtr) {
    final len = bufPtr.ref.len;
    final data = Uint8List.fromList(bufPtr.ref.data.asTypedList(len));
    _bindings.sibna_free_buffer(bufPtr);
    return data;
  }

  /// Ensure the session is not disposed
  void _ensureNotDisposed() {
    if (_disposed) {
      throw SibnaError(
        SibnaErrorCode.invalidState,
        'Session has been disposed',
      );
    }
  }

  @override
  String toString() =>
    'SibnaSession(peerId: ${_peerId.toHex().substring(0, 16)}..., '
    'messages: $_messagesSent/$_messagesReceived, '
    'established: $isEstablished)';
}
