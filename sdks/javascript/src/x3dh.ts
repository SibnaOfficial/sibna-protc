/**
 * Sibna Protocol v3.0.1 — X3DH (JavaScript)
 */

import { KEY_LENGTH, X25519KeyPair, blake3Hash, hkdfDerive } from './crypto';

export interface PreKeyBundle {
  identityKey: Uint8Array;          // Ed25519 public key (32 bytes)
  x25519IdentityKey: Uint8Array;    // X25519 public key (32 bytes) — for DH
  signedPrekey: Uint8Array;         // X25519 public key (32 bytes)
  signedPrekeySignature: Uint8Array; // Ed25519 signature (64 bytes)
  onetimePrekey?: Uint8Array;       // X25519 public key (32 bytes, optional)
  registrationId?: number;
  deviceId?: number;
}

export interface X3DHResult {
  sharedSecret: Uint8Array;
  dhResults: Uint8Array[];
}

const EMPTY_16 = new Uint8Array(16);
const EMPTY_32 = new Uint8Array(32);

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

function deriveSharedSecret(
  dh1: Uint8Array, dh2: Uint8Array, dh3: Uint8Array,
  dh4: Uint8Array | null, transcriptHash: Uint8Array,
): Uint8Array {
  const parts = dh4 ? concatBytes(dh1, dh2, dh3, dh4) : concatBytes(dh1, dh2, dh3);
  return hkdfDerive(parts, transcriptHash, new TextEncoder().encode('SibnaX3DH_v3'), KEY_LENGTH);
}

export function x3dhInitiator(
  identityKeypair: X25519KeyPair,
  ephemeralKeypair: X25519KeyPair,
  peerBundle: PreKeyBundle,
  ourDeviceId: Uint8Array = EMPTY_16,
  peerDeviceId: Uint8Array = EMPTY_16,
  transcriptHashExt: Uint8Array = EMPTY_32,
): X3DHResult {
  const dh1 = identityKeypair.dh(peerBundle.signedPrekey);
  const dh2 = ephemeralKeypair.dh(peerBundle.x25519IdentityKey);
  const dh3 = ephemeralKeypair.dh(peerBundle.signedPrekey);

  const dhResults: Uint8Array[] = [dh1, dh2, dh3];
  let dh4: Uint8Array | null = null;
  if (peerBundle.onetimePrekey) {
    dh4 = ephemeralKeypair.dh(peerBundle.onetimePrekey);
    dhResults.push(dh4);
  }

  const parts: Uint8Array[] = [
    identityKeypair.publicKey, ephemeralKeypair.publicKey,
    peerBundle.x25519IdentityKey, peerBundle.signedPrekey,
  ];
  if (peerBundle.onetimePrekey) parts.push(peerBundle.onetimePrekey);
  parts.push(ourDeviceId, peerDeviceId);

  const transcriptHash = blake3Hash(...parts);
  const combinedTranscript = hkdfDerive(
    transcriptHash, transcriptHashExt,
    new TextEncoder().encode('SibnaX3DH_TranscriptBind_v3'), 32,
  );

  const sharedSecret = deriveSharedSecret(dh1, dh2, dh3, dh4, combinedTranscript);

  return { sharedSecret, dhResults };
}

export function x3dhResponder(
  identityKeypair: X25519KeyPair,
  signedPrekeypair: X25519KeyPair,
  onetimePrekeypair: X25519KeyPair | null,
  peerIdentity: Uint8Array,
  peerEphemeral: Uint8Array,
  ourDeviceId: Uint8Array = EMPTY_16,
  peerDeviceId: Uint8Array = EMPTY_16,
  transcriptHashExt: Uint8Array = EMPTY_32,
): X3DHResult {
  const dh1 = signedPrekeypair.dh(peerIdentity);
  const dh2 = identityKeypair.dh(peerEphemeral);
  const dh3 = signedPrekeypair.dh(peerEphemeral);

  const dhResults: Uint8Array[] = [dh1, dh2, dh3];
  let dh4: Uint8Array | null = null;
  if (onetimePrekeypair) {
    dh4 = onetimePrekeypair.dh(peerEphemeral);
    dhResults.push(dh4);
  }

  const parts: Uint8Array[] = [
    peerIdentity, peerEphemeral,
    identityKeypair.publicKey, signedPrekeypair.publicKey,
  ];
  if (onetimePrekeypair) parts.push(onetimePrekeypair.publicKey);
  parts.push(peerDeviceId, ourDeviceId);

  const transcriptHash = blake3Hash(...parts);
  const combinedTranscript = hkdfDerive(
    transcriptHash, transcriptHashExt,
    new TextEncoder().encode('SibnaX3DH_TranscriptBind_v3'), 32,
  );

  const sharedSecret = deriveSharedSecret(dh1, dh2, dh3, dh4, combinedTranscript);

  return { sharedSecret, dhResults };
}
