part of '../sibna_protocol.dart';

/// Group session for group messaging
class SibnaGroup {
  final Uint8List _groupId;
  final List<Uint8List> _members = [];
  final Map<String, Uint8List> _senderKeys = {};
  int _epoch = 0;
  DateTime? _createdAt;
  DateTime? _lastActivity;
  bool _disposed = false;

  /// Get the group ID
  Uint8List get groupId => Uint8List.fromList(_groupId);

  /// Get the current epoch
  int get epoch => _epoch;

  /// Get the number of members
  int get memberCount => _members.length;

  /// Get the list of members
  List<Uint8List> get members =>
    _members.map((m) => Uint8List.fromList(m)).toList();

  /// Get the creation time
  DateTime? get createdAt => _createdAt;

  /// Get the last activity time
  DateTime? get lastActivity => _lastActivity;

  /// Check if the group is disposed
  bool get isDisposed => _disposed;

  /// Private constructor
  SibnaGroup._(this._groupId) {
    _createdAt = DateTime.now();
    _lastActivity = _createdAt;
  }

  /// Factory constructor to create a new group
  factory SibnaGroup._create(Uint8List groupId) {
    return SibnaGroup._(groupId);
  }

  /// Add a member to the group
  Future<void> addMember(Uint8List publicKey) async {
    _ensureNotDisposed();

    if (publicKey.length != 32) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Public key must be 32 bytes',
        field: 'publicKey',
      );
    }

    // Check for duplicate
    for (final member in _members) {
      if (SibnaUtils.constantTimeEquals(member, publicKey)) {
        throw SibnaError(
          SibnaErrorCode.invalidArgument,
          'Member already exists in group',
        );
      }
    }

    _members.add(Uint8List.fromList(publicKey));
    _epoch++;
    _touch();
  }

  /// Remove a member from the group
  Future<void> removeMember(Uint8List publicKey) async {
    _ensureNotDisposed();

    _members.removeWhere((m) => SibnaUtils.constantTimeEquals(m, publicKey));
    _senderKeys.removeWhere((k, v) {
      final keyBytes = SibnaUtils.hexToBytes(k);
      return SibnaUtils.constantTimeEquals(keyBytes, publicKey);
    });
    _epoch++;
    _touch();
  }

  /// Import a sender key from a member
  Future<void> importSenderKey(
    Uint8List memberPublicKey,
    Uint8List senderKey,
  ) async {
    _ensureNotDisposed();

    if (senderKey.length != 32) {
      throw ValidationError(
        SibnaErrorCode.invalidKey,
        'Sender key must be 32 bytes',
        field: 'senderKey',
      );
    }

    final keyHex = memberPublicKey.toHex();
    _senderKeys[keyHex] = Uint8List.fromList(senderKey);
    _touch();
  }

  /// Encrypt a group message
  Future<GroupMessage> encrypt(Uint8List plaintext) async {
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
        'Message too large',
        field: 'plaintext',
      );
    }

    // Generate sender key for this message
    final senderKey = SibnaCrypto.generateKey();

    try {
      final ciphertext = SibnaCrypto.encrypt(
        senderKey,
        plaintext,
        associatedData: _groupId,
      );

      _touch();

      return GroupMessage(
        groupId: Uint8List.fromList(_groupId),
        senderKeyId: _epoch,
        messageNumber: _senderKeys.length,
        ciphertext: ciphertext,
        epoch: _epoch,
        timestamp: DateTime.now(),
      );
    } finally {
      senderKey.secureClear();
    }
  }

  /// Decrypt a group message
  Future<Uint8List> decrypt(
    GroupMessage message,
    Uint8List senderPublicKey,
  ) async {
    _ensureNotDisposed();

    // Validate group ID
    if (!SibnaUtils.constantTimeEquals(message.groupId, _groupId)) {
      throw SibnaError(
        SibnaErrorCode.invalidMessage,
        'Message is for a different group',
      );
    }

    // Check epoch
    if (message.epoch < _epoch) {
      throw SibnaError(
        SibnaErrorCode.invalidMessage,
        'Message epoch is outdated',
      );
    }

    // Get sender key
    final keyHex = senderPublicKey.toHex();
    final senderKey = _senderKeys[keyHex];

    if (senderKey == null) {
      throw SibnaError(
        SibnaErrorCode.keyNotFound,
        'Sender key not found for member',
      );
    }

    try {
      final plaintext = SibnaCrypto.decrypt(
        senderKey,
        message.ciphertext,
        associatedData: _groupId,
      );

      _touch();
      return plaintext;
    } catch (e) {
      throw CryptoError(
        SibnaErrorCode.decryptionFailed,
        'Failed to decrypt group message: $e',
      );
    }
  }

  /// Leave the group
  Future<void> leave() async {
    _ensureNotDisposed();

    // Clear all sender keys
    for (final key in _senderKeys.values) {
      key.secureClear();
    }
    _senderKeys.clear();

    _members.clear();
    _epoch = 0;
  }

  /// Update last activity timestamp
  void _touch() {
    _lastActivity = DateTime.now();
  }

  /// Ensure the group is not disposed
  void _ensureNotDisposed() {
    if (_disposed) {
      throw SibnaError(
        SibnaErrorCode.invalidState,
        'Group has been disposed',
      );
    }
  }

  /// Dispose the group and free resources
  void dispose() {
    if (_disposed) return;

    // Securely clear all keys
    for (final key in _senderKeys.values) {
      key.secureClear();
    }
    _senderKeys.clear();

    // Clear member list
    for (final member in _members) {
      member.secureClear();
    }
    _members.clear();

    // Clear group ID
    _groupId.secureClear();

    _disposed = true;
  }

  /// Get group statistics
  Map<String, dynamic> get stats => {
    'groupId': _groupId.toHex(),
    'memberCount': _members.length,
    'epoch': _epoch,
    'createdAt': _createdAt?.toIso8601String(),
    'lastActivity': _lastActivity?.toIso8601String(),
  };

  @override
  String toString() =>
    'SibnaGroup(id: ${_groupId.toHex().substring(0, 16)}..., '
    'members: ${_members.length}, epoch: $_epoch)';
}

/// Group message structure
class GroupMessage {
  /// Group ID
  final Uint8List groupId;

  /// Sender key identifier
  final int senderKeyId;

  /// Message number
  final int messageNumber;

  /// Encrypted content
  final Uint8List ciphertext;

  /// Group epoch
  final int epoch;

  /// Timestamp
  final DateTime timestamp;

  /// Create a new group message
  GroupMessage({
    required this.groupId,
    required this.senderKeyId,
    required this.messageNumber,
    required this.ciphertext,
    required this.epoch,
    required this.timestamp,
  });

  /// Serialize to bytes
  Uint8List toBytes() {
    final builder = BytesBuilder()
      ..add(groupId)
      ..add(_intToBytes(senderKeyId))
      ..add(_intToBytes(messageNumber))
      ..add(_intToBytes(ciphertext.length))
      ..add(ciphertext)
      ..add(_intToBytes(epoch))
      ..add(_int64ToBytes(timestamp.millisecondsSinceEpoch ~/ 1000));

    return builder.toBytes();
  }

  /// Deserialize from bytes
  factory GroupMessage.fromBytes(Uint8List bytes) {
    var offset = 0;

    final groupId = bytes.sublist(offset, offset + 32);
    offset += 32;

    final senderKeyId = _bytesToInt(bytes.sublist(offset, offset + 4));
    offset += 4;

    final messageNumber = _bytesToInt(bytes.sublist(offset, offset + 4));
    offset += 4;

    final ciphertextLen = _bytesToInt(bytes.sublist(offset, offset + 4));
    offset += 4;

    final ciphertext = bytes.sublist(offset, offset + ciphertextLen);
    offset += ciphertextLen;

    final epoch = _bytesToInt(bytes.sublist(offset, offset + 4));
    offset += 4;

    final timestampSeconds = _bytesToInt64(bytes.sublist(offset, offset + 8));

    return GroupMessage(
      groupId: groupId,
      senderKeyId: senderKeyId,
      messageNumber: messageNumber,
      ciphertext: ciphertext,
      epoch: epoch,
      timestamp: DateTime.fromMillisecondsSinceEpoch(timestampSeconds * 1000),
    );
  }

  /// Check if the message has expired (older than 24 hours)
  bool get isExpired {
    final now = DateTime.now();
    return now.difference(timestamp).inHours > 24;
  }

  static Uint8List _intToBytes(int value) {
    final data = ByteData(4)..setUint32(0, value, Endian.little);
    return data.buffer.asUint8List();
  }

  static Uint8List _int64ToBytes(int value) {
    final data = ByteData(8)..setUint64(0, value, Endian.little);
    return data.buffer.asUint8List();
  }

  static int _bytesToInt(Uint8List bytes) {
    final data = ByteData.sublistView(bytes);
    return data.getUint32(0, Endian.little);
  }

  static int _bytesToInt64(Uint8List bytes) {
    final data = ByteData.sublistView(bytes);
    return data.getUint64(0, Endian.little);
  }

  @override
  String toString() =>
    'GroupMessage(groupId: ${groupId.toHex().substring(0, 16)}..., '
    'epoch: $epoch, expired: $isExpired)';
}
