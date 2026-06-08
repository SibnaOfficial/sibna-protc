/// Sibna Protocol v3.0.1 — Extended Triple Diffie-Hellman (X3DH)
///
/// Matches the Rust core implementation exactly:
///   - Transcript hash via Blake3 (fallback SHA-256)
///   - HKDF-based transcript binding with "SibnaX3DH_TranscriptBind_v3"
///   - Shared secret derivation via HKDF with "SibnaX3DH_v3"
///   - DH computation order: initiator and responder perspectives
///   - X25519 identity key for DH, Ed25519 identity key for signing
import 'dart:convert';
import 'dart:typed_data';

import 'crypto.dart';

// ── PreKeyBundle ────────────────────────────────────────────────────────────

/// PreKeyBundle for X3DH handshake.
///
/// [identityKey]: Ed25519 public key (32 bytes) — used for signature verification
/// [x25519IdentityKey]: X25519 public key (32 bytes) — used for DH in X3DH
/// [signedPrekey]: X25519 public key (32 bytes) — used for DH
/// [signedPrekeySignature]: Ed25519 signature (64 bytes) — over signed_prekey
class PreKeyBundle {
  /// Ed25519 public key (32 bytes) — for signature verification.
  final Uint8List identityKey;

  /// X25519 public key (32 bytes) — for DH in X3DH.
  final Uint8List x25519IdentityKey;

  /// X25519 public key (32 bytes) — signed prekey for DH.
  final Uint8List signedPrekey;

  /// Ed25519 signature (64 bytes) — over signed_prekey.
  final Uint8List signedPrekeySignature;

  /// Optional X25519 public key (32 bytes) — one-time prekey.
  final Uint8List? onetimePrekey;

  /// Registration ID.
  final int registrationId;

  /// Device ID.
  final int deviceId;

  PreKeyBundle({
    required this.identityKey,
    required this.x25519IdentityKey,
    required this.signedPrekey,
    required this.signedPrekeySignature,
    this.onetimePrekey,
    this.registrationId = 0,
    this.deviceId = 0,
  });

  /// Standalone bundles never expire.
  bool get isExpired => false;
}

// ── X3DH Result ─────────────────────────────────────────────────────────────

/// Result of X3DH key agreement.
class X3DHResult {
  /// 32-byte derived shared secret.
  final Uint8List sharedSecret;

  /// List of raw DH outputs.
  final List<Uint8List> dhResults;

  X3DHResult({
    required this.sharedSecret,
    required this.dhResults,
  });
}

// ── X3DH Initiator ──────────────────────────────────────────────────────────

/// X3DH key agreement — initiator side.
///
/// DH1 = DH(our_identity_x25519, peer_spk)
/// DH2 = DH(our_ephemeral, peer_identity_x25519)
/// DH3 = DH(our_ephemeral, peer_spk)
/// DH4 = DH(our_ephemeral, peer_opk)  [optional]
Future<X3DHResult> x3DHInitiator({
  required X25519KeyPair identityKeypair,
  required X25519KeyPair ephemeralKeypair,
  required PreKeyBundle peerBundle,
  Uint8List? ourDeviceId,
  Uint8List? peerDeviceId,
  Uint8List? transcriptHashExt,
}) async {
  final ourDev = ourDeviceId ?? Uint8List(16);
  final peerDev = peerDeviceId ?? Uint8List(16);
  final transExt = transcriptHashExt ?? Uint8List(32);

  // DH computations — using X25519 identity key for DH (not Ed25519)
  final dh1 = await identityKeypair.dh(peerBundle.signedPrekey);
  final dh2 = await ephemeralKeypair.dh(peerBundle.x25519IdentityKey);
  final dh3 = await ephemeralKeypair.dh(peerBundle.signedPrekey);

  final dhResults = <Uint8List>[dh1, dh2, dh3];
  Uint8List? dh4;

  if (peerBundle.onetimePrekey != null) {
    dh4 = await ephemeralKeypair.dh(peerBundle.onetimePrekey!);
    dhResults.add(dh4);
  }

  // Transcript hash (only PUBLIC keys — matching Rust x3dh_initiator_v3)
  // Order: [our_id, our_eph, peer_id, peer_spk, opt(peer_opk), our_dev, peer_dev]
  final parts = <Uint8List>[
    identityKeypair.publicKey,
    ephemeralKeypair.publicKey,
    peerBundle.x25519IdentityKey,
    peerBundle.signedPrekey,
  ];
  if (peerBundle.onetimePrekey != null) {
    parts.add(peerBundle.onetimePrekey!);
  }
  parts.addAll([ourDev, peerDev]);

  final transcriptHash = await blake3Hash(parts);

  // HKDF-based transcript binding
  final combinedTranscript = hkdf(
    transcriptHash,
    salt: transExt,
    info: Uint8List.fromList([
      ...utf8.encode('SibnaX3DH_TranscriptBind_v3'),
    ]),
    length: 32,
  );

  // Derive shared secret
  final sharedSecret =
      _deriveSharedSecret(dh1, dh2, dh3, dh4, combinedTranscript);

  return X3DHResult(
    sharedSecret: sharedSecret,
    dhResults: dhResults,
  );
}

// ── X3DH Responder ──────────────────────────────────────────────────────────

/// X3DH key agreement — responder side.
///
/// DH1 = DH(our_spk, peer_identity)
/// DH2 = DH(our_identity, peer_ephemeral)
/// DH3 = DH(our_spk, peer_ephemeral)
/// DH4 = DH(our_opk, peer_ephemeral)  [optional]
Future<X3DHResult> x3DHResponder({
  required X25519KeyPair identityKeypair,
  required X25519KeyPair signedPrekeypair,
  X25519KeyPair? onetimePrekeypair,
  required Uint8List peerIdentity,
  required Uint8List peerEphemeral,
  Uint8List? ourDeviceId,
  Uint8List? peerDeviceId,
  Uint8List? transcriptHashExt,
}) async {
  final ourDev = ourDeviceId ?? Uint8List(16);
  final peerDev = peerDeviceId ?? Uint8List(16);
  final transExt = transcriptHashExt ?? Uint8List(32);

  // DH computations (note: perspective is reversed from initiator)
  final dh1 = await signedPrekeypair.dh(peerIdentity);
  final dh2 = await identityKeypair.dh(peerEphemeral);
  final dh3 = await signedPrekeypair.dh(peerEphemeral);

  final dhResults = <Uint8List>[dh1, dh2, dh3];
  Uint8List? dh4;

  if (onetimePrekeypair != null) {
    dh4 = await onetimePrekeypair.dh(peerEphemeral);
    dhResults.add(dh4);
  }

  // Transcript hash (matching Rust x3dh_responder_v3 order)
  // From responder's view: [peer_id, peer_eph, our_id, our_spk, opt(our_opk), peer_dev, our_dev]
  final parts = <Uint8List>[
    peerIdentity,
    peerEphemeral,
    identityKeypair.publicKey,
    signedPrekeypair.publicKey,
  ];
  if (onetimePrekeypair != null) {
    parts.add(onetimePrekeypair.publicKey);
  }
  parts.addAll([peerDev, ourDev]);

  final transcriptHash = await blake3Hash(parts);

  // HKDF-based transcript binding
  final combinedTranscript = hkdf(
    transcriptHash,
    salt: transExt,
    info: Uint8List.fromList([
      ...utf8.encode('SibnaX3DH_TranscriptBind_v3'),
    ]),
    length: 32,
  );

  // Derive shared secret
  final sharedSecret =
      _deriveSharedSecret(dh1, dh2, dh3, dh4, combinedTranscript);

  return X3DHResult(
    sharedSecret: sharedSecret,
    dhResults: dhResults,
  );
}

// ── Shared Secret Derivation ────────────────────────────────────────────────

/// Derive X3DH shared secret from DH outputs.
/// Matches Rust X3dhKdf::derive_shared_secret().
Uint8List _deriveSharedSecret(
  Uint8List dh1,
  Uint8List dh2,
  Uint8List dh3,
  Uint8List? dh4,
  Uint8List transcriptHash,
) {
  final concatenated = Uint8List.fromList([
    ...dh1,
    ...dh2,
    ...dh3,
    if (dh4 != null) ...dh4,
  ]);

  return hkdf(
    concatenated,
    salt: transcriptHash,
    info: Uint8List.fromList([
      ...utf8.encode('SibnaX3DH_v3'),
    ]),
    length: keyLength,
  );
}
