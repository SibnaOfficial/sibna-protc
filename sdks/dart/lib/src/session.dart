/// Sibna Protocol v3.0.1 — Session Management
///
/// High-level session that combines X3DH handshake with Double Ratchet
/// encryption. Matches the Rust core's DoubleRatchetSession API.
import 'dart:typed_data';

import 'crypto.dart';
import 'ratchet.dart';
import 'x3dh.dart';

// ── Session Config ──────────────────────────────────────────────────────────

/// Session configuration.
class SessionConfig {
  final int maxSkippedMessages;
  final int maxChainMessages;

  SessionConfig({
    int? maxSkippedMessages,
    int? maxChainMessages,
  })  : maxSkippedMessages = maxSkippedMessages ?? 2000,
        maxChainMessages = maxChainMessages ?? 4000;
}

// ── Session ─────────────────────────────────────────────────────────────────

/// Encrypted session combining X3DH + Double Ratchet.
class Session {
  DoubleRatchet? _ratchet;
  final String _sessionId;
  DateTime? _establishedAt;
  Uint8List? _peerId;

  Session({SessionConfig? config}) : _sessionId = _generateSessionId();

  /// Unique session identifier.
  String get sessionId => _sessionId;

  /// Whether the session is established (ratchet initialized).
  bool get isEstablished => _ratchet != null;

  /// When the session was established.
  DateTime? get establishedAt => _establishedAt;

  /// The peer's identity key (Ed25519 public key bytes).
  Uint8List? get peerId => _peerId;

  /// Number of messages sent.
  int get messagesSent => _ratchet?.messagesSent ?? 0;

  /// Number of messages received.
  int get messagesReceived => _ratchet?.messagesReceived ?? 0;

  // ── Initiator (who creates the session first) ───────────────────────

  /// Perform X3DH as initiator and initialize the Double Ratchet.
  ///
  /// Returns the ephemeral public key (sent to responder).
  Future<Uint8List> initiateAsInitiator({
    required X25519KeyPair identity,
    required X25519KeyPair ephemeral,
    required PreKeyBundle peerBundle,
    Uint8List? ourDeviceId,
    Uint8List? peerDeviceId,
  }) async {
    final result = await x3DHInitiator(
      identityKeypair: identity,
      ephemeralKeypair: ephemeral,
      peerBundle: peerBundle,
      ourDeviceId: ourDeviceId,
      peerDeviceId: peerDeviceId,
    );

    final ephemeralPrivateBytes = await ephemeral.privateKey;

    _ratchet = await DoubleRatchet.fromSharedSecret(
      sharedSecret: result.sharedSecret,
      localDhPrivate: ephemeralPrivateBytes,
      remoteDhPublic: peerBundle.signedPrekey,
      roleIsInitiator: true,
    );
    _establishedAt = DateTime.now();
    _peerId = peerBundle.identityKey;

    return ephemeral.publicKey;
  }

  // ── Responder (who receives the first message) ──────────────────────

  /// Perform X3DH as responder and initialize the Double Ratchet.
  Future<void> initiateAsResponder({
    required X25519KeyPair identity,
    required X25519KeyPair signedPrekey,
    X25519KeyPair? onetimePrekey,
    required Uint8List peerIdentity,
    required Uint8List peerEphemeral,
    Uint8List? ourDeviceId,
    Uint8List? peerDeviceId,
  }) async {
    final result = await x3DHResponder(
      identityKeypair: identity,
      signedPrekeypair: signedPrekey,
      onetimePrekeypair: onetimePrekey,
      peerIdentity: peerIdentity,
      peerEphemeral: peerEphemeral,
      ourDeviceId: ourDeviceId,
      peerDeviceId: peerDeviceId,
    );

    final signedPrekeyPrivateBytes = await signedPrekey.privateKey;

    _ratchet = await DoubleRatchet.fromSharedSecret(
      sharedSecret: result.sharedSecret,
      localDhPrivate: signedPrekeyPrivateBytes,
      remoteDhPublic: peerEphemeral,
      roleIsInitiator: false,
    );
    _establishedAt = DateTime.now();
    _peerId = peerIdentity;
  }

  // ── Restore from known shared secret (testing) ──────────────────────

  /// Restore a session from a known shared secret (for testing).
  static Future<Session> fromSharedSecret({
    required Uint8List sharedSecret,
    required Uint8List localDhPrivate,
    required Uint8List remoteDhPublic,
    required bool roleIsInitiator,
    SessionConfig? config,
  }) async {
    final s = Session(config: config);
    s._ratchet = await DoubleRatchet.fromSharedSecret(
      sharedSecret: sharedSecret,
      localDhPrivate: localDhPrivate,
      remoteDhPublic: remoteDhPublic,
      roleIsInitiator: roleIsInitiator,
    );
    s._establishedAt = DateTime.now();
    return s;
  }

  // ── Encrypt / Decrypt ───────────────────────────────────────────────

  /// Encrypt a message.
  Future<Uint8List> encrypt(
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) async {
    if (_ratchet == null) throw StateError('Session not established');
    return _ratchet!.ratchetEncrypt(plaintext, associatedData: associatedData);
  }

  /// Decrypt a message.
  Future<Uint8List> decrypt(
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) async {
    if (_ratchet == null) throw StateError('Session not established');
    return _ratchet!.ratchetDecrypt(ciphertext, associatedData: associatedData);
  }

  // ── Serialization ───────────────────────────────────────────────────

  /// Export session state for persistence.
  Map<String, dynamic>? exportState() {
    if (_ratchet == null) return null;
    final r = _ratchet!;
    return {
      'sessionId': _sessionId,
      'rootKey': bytesToHex(r.rootKey),
      'dhLocalPrivate':
          r.dhLocalPrivate != null ? bytesToHex(r.dhLocalPrivate!) : null,
      'dhLocalPublic':
          r.dhLocalPublic != null ? bytesToHex(r.dhLocalPublic!) : null,
      'dhRemotePublic':
          r.dhRemotePublic != null ? bytesToHex(r.dhRemotePublic!) : null,
      'sendingChainKey':
          r.sendingChain != null ? bytesToHex(r.sendingChain!.key) : null,
      'sendingChainIndex': r.sendingChain?.index ?? 0,
      'receivingChainKey':
          r.receivingChain != null ? bytesToHex(r.receivingChain!.key) : null,
      'receivingChainIndex': r.receivingChain?.index ?? 0,
      'messagesSent': r.messagesSent,
      'messagesReceived': r.messagesReceived,
      'previousCounter': r.previousCounter,
    };
  }

  @override
  String toString() {
    final peerHex =
        _peerId != null ? bytesToHex(_peerId!).substring(0, 16) : 'None';
    return 'Session(id: ${_sessionId.substring(0, 8)}..., '
        'peer: $peerHex..., '
        'sent: $messagesSent, recv: $messagesReceived, '
        'established: $isEstablished)';
  }

  // ── Helpers ─────────────────────────────────────────────────────────

  static String _generateSessionId() {
    final bytes = randomBytes(16);
    return bytesToHex(bytes);
  }
}
