part of '../sibna_flutter.dart';

class SibnaGroupMessage {
  final Uint8List groupId;
  final Uint8List ciphertext;
  final int epoch;
  final int timestamp;

  const SibnaGroupMessage({
    required this.groupId,
    required this.ciphertext,
    required this.epoch,
    required this.timestamp,
  });
}

/// Group session — sender-key based group E2EE.
///
/// Note: Full group messaging requires the native sibna_group_* FFI functions
/// to be exposed. This class will be completed in a future release.
class SibnaGroup {
  final Uint8List groupId;
  bool _disposed = false;

  SibnaGroup._(this.groupId);

  /// Create a new group with a random 32-byte group ID.
  static SibnaGroup create() {
    // Group ID will be generated via randomBytes in production
    throw UnimplementedError(
      'Group creation requires sibna_group_create() FFI binding. '
      'Use the Rust core directly until FFI bindings are exposed.',
    );
  }

  void dispose() => _disposed = true;

  @override
  String toString() => 'SibnaGroup(id: ${groupId.take(4).toList()})';
}
