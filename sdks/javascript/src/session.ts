/**
 * Sibna Protocol v3.0.1 — Session (JavaScript)
 */

import { X25519KeyPair } from './crypto';
import { DoubleRatchet } from './ratchet';
import { PreKeyBundle, x3dhInitiator, x3dhResponder } from './x3dh';

export interface SessionConfig {
  maxSkippedMessages?: number;
  maxChainMessages?: number;
}

export class Session {
  private _ratchet: DoubleRatchet | null = null;
  private _sessionId: string;
  private _establishedAt: number | null = null;
  private _peerId: Uint8Array | null = null;

  constructor() {
    this._sessionId = crypto.randomUUID();
  }

  get sessionId(): string { return this._sessionId; }
  get isEstablished(): boolean { return this._ratchet !== null; }
  get establishedAt(): number | null { return this._establishedAt; }
  get peerId(): Uint8Array | null { return this._peerId ? new Uint8Array(this._peerId) : null; }
  get messagesSent(): number { return this._ratchet?.messagesSent ?? 0; }
  get messagesReceived(): number { return this._ratchet?.messagesReceived ?? 0; }

  initiateAsInitiator(
    identity: X25519KeyPair,
    ephemeral: X25519KeyPair,
    peerBundle: PreKeyBundle,
    ourDeviceId: Uint8Array = new Uint8Array(16),
    peerDeviceId: Uint8Array = new Uint8Array(16),
  ): Uint8Array {
    const result = x3dhInitiator(identity, ephemeral, peerBundle, ourDeviceId, peerDeviceId);
    this._ratchet = DoubleRatchet.fromSharedSecret(
      result.sharedSecret, ephemeral.privateKey, peerBundle.signedPrekey, true,
    );
    this._establishedAt = Date.now();
    this._peerId = new Uint8Array(peerBundle.x25519IdentityKey);
    return ephemeral.publicKey;
  }

  initiateAsResponder(
    identity: X25519KeyPair,
    signedPrekey: X25519KeyPair,
    onetimePrekey: X25519KeyPair | null,
    peerIdentity: Uint8Array,
    peerEphemeral: Uint8Array,
    ourDeviceId: Uint8Array = new Uint8Array(16),
    peerDeviceId: Uint8Array = new Uint8Array(16),
  ): void {
    const result = x3dhResponder(
      identity, signedPrekey, onetimePrekey, peerIdentity, peerEphemeral, ourDeviceId, peerDeviceId,
    );
    this._ratchet = DoubleRatchet.fromSharedSecret(
      result.sharedSecret, signedPrekey.privateKey, peerEphemeral, false,
    );
    this._establishedAt = Date.now();
    this._peerId = new Uint8Array(peerIdentity);
  }

  static fromSharedSecret(
    sharedSecret: Uint8Array,
    localDhPrivate: Uint8Array,
    remoteDhPublic: Uint8Array,
    isInitiator: boolean,
  ): Session {
    const s = new Session();
    s._ratchet = DoubleRatchet.fromSharedSecret(sharedSecret, localDhPrivate, remoteDhPublic, isInitiator);
    s._establishedAt = Date.now();
    return s;
  }

  encrypt(plaintext: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (!this._ratchet) throw new Error('Session not established');
    return this._ratchet.ratchetEncrypt(plaintext, associatedData);
  }

  decrypt(ciphertext: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (!this._ratchet) throw new Error('Session not established');
    return this._ratchet.ratchetDecrypt(ciphertext, associatedData);
  }
}
