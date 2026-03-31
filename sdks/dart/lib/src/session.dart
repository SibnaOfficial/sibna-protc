part of '../sibna_protocol.dart';

/// Secure session for encrypted communication
class SibnaSession {
  Pointer<Void>? _handle;
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

  /// Private constructor
  SibnaSession._(this._handle, this._peerId) {
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

    // This would use the session's ratchet in production
    // For now, use standalone crypto
    final key = SibnaCrypto.generateKey();
    try {
      final ciphertext = SibnaCrypto.encrypt(
        key,
        plaintext,
        associatedData: associatedData,
      );
      _messagesSent++;
      return ciphertext;
    } finally {
      key.secureClear();
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

    // This would use the session's ratchet in production
    throw UnimplementedError('Session-based decryption requires native library');
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

    if (_handle != null && _handle != nullptr) {
      _bindings.sibna_session_destroy(_handle!);
      _handle = null;
    }

    // Securely clear peer ID
    _peerId.secureClear();

    _disposed = true;
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
