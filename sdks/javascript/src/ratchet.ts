/**
 * Sibna Protocol v3.0.1 — Double Ratchet (JavaScript)
 *
 * Matches the Rust core exactly:
 * - Chain key: HMAC-SHA256(ck, 0x01) = mk, HMAC-SHA256(ck, 0x02) = next_ck
 * - Root KDF: HKDF(root, dh_out, "SibnaRatchet_v3")
 * - Initial: HKDF(shared_secret, "SibnaSession_v3", "SibnaRootAndChainKey_v3")
 * - Wire: dh_public(32) || msg_num(4) || nonce(12) || ct+tag
 */

import {
  KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH,
  X25519KeyPair,
  chacha20Poly1305Encrypt, chacha20Poly1305Decrypt,
  hkdfDerive, hmacSha256, randomBytesExport,
} from './crypto';

const MESSAGE_KEY_SEED = new Uint8Array([0x01]);
const CHAIN_KEY_SEED = new Uint8Array([0x02]);
const HEADER_KEY_SEED = new Uint8Array([0x03]);

const INITIAL_KDF_SALT = new TextEncoder().encode('SibnaSession_v3');
const INITIAL_KDF_INFO = new TextEncoder().encode('SibnaRootAndChainKey_v3');
const DH_RATCHET_INFO = new TextEncoder().encode('SibnaRatchet_v3');

export const MAX_CHAIN_MESSAGES = 4000;
export const MAX_SKIPPED_MESSAGES = 2000;

// ── Chain Key ───────────────────────────────────────────────────────────────

export class ChainKey {
  key: Uint8Array;
  index: number;
  maxMessages: number;

  constructor(key: Uint8Array, index = 0, maxMessages = MAX_CHAIN_MESSAGES) {
    this.key = new Uint8Array(key);
    this.index = index;
    this.maxMessages = maxMessages;
  }

  nextMessageKey(): [Uint8Array, ChainKey] | null {
    if (this.index >= this.maxMessages) return null;
    const mk = hmacSha256(this.key, MESSAGE_KEY_SEED);
    const nextCk = hmacSha256(this.key, CHAIN_KEY_SEED);
    return [mk, new ChainKey(nextCk, this.index + 1, this.maxMessages)];
  }

  deriveHeaderKey(): Uint8Array {
    return hmacSha256(this.key, HEADER_KEY_SEED);
  }

  remainingMessages(): number {
    return Math.max(0, this.maxMessages - this.index);
  }

  clone(): ChainKey {
    return new ChainKey(new Uint8Array(this.key), this.index, this.maxMessages);
  }
}

// ── Double Ratchet ──────────────────────────────────────────────────────────

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function packUint32LE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = n & 0xFF;
  buf[1] = (n >>> 8) & 0xFF;
  buf[2] = (n >>> 16) & 0xFF;
  buf[3] = (n >>> 24) & 0xFF;
  return buf;
}

function unpackUint32LE(buf: Uint8Array, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24);
}

export class DoubleRatchet {
  rootKey: Uint8Array;
  sendingChain: ChainKey | null;
  receivingChain: ChainKey | null;
  dhLocalPrivate: Uint8Array | null;
  dhLocalPublic: Uint8Array | null;
  dhRemotePublic: Uint8Array | null;
  previousCounter: number;
  maxSkip: number;
  skippedKeys: Map<string, Uint8Array>;
  messagesSent: number;
  messagesReceived: number;
  createdAt: number;

  constructor(params: {
    rootKey: Uint8Array;
    sendingChain?: ChainKey | null;
    receivingChain?: ChainKey | null;
    dhLocalPrivate?: Uint8Array | null;
    dhLocalPublic?: Uint8Array | null;
    dhRemotePublic?: Uint8Array | null;
    previousCounter?: number;
    maxSkip?: number;
  }) {
    this.rootKey = new Uint8Array(params.rootKey);
    this.sendingChain = params.sendingChain ?? null;
    this.receivingChain = params.receivingChain ?? null;
    this.dhLocalPrivate = params.dhLocalPrivate ? new Uint8Array(params.dhLocalPrivate) : null;
    this.dhLocalPublic = params.dhLocalPublic ? new Uint8Array(params.dhLocalPublic) : null;
    this.dhRemotePublic = params.dhRemotePublic ? new Uint8Array(params.dhRemotePublic) : null;
    this.previousCounter = params.previousCounter ?? 0;
    this.maxSkip = params.maxSkip ?? MAX_SKIPPED_MESSAGES;
    this.skippedKeys = new Map();
    this.messagesSent = 0;
    this.messagesReceived = 0;
    this.createdAt = Date.now();
  }

  static fromSharedSecret(
    sharedSecret: Uint8Array,
    localDhPrivate: Uint8Array,
    remoteDhPublic: Uint8Array,
    roleIsInitiator: boolean,
  ): DoubleRatchet {
    const okm = hkdfDerive(sharedSecret, INITIAL_KDF_SALT, INITIAL_KDF_INFO, 64);
    const rootKey = okm.slice(0, 32);
    const chainKey = okm.slice(32);
    const localPub = X25519KeyPair.fromPrivateBytes(localDhPrivate).publicKey;

    return new DoubleRatchet({
      rootKey,
      sendingChain: roleIsInitiator ? new ChainKey(chainKey) : null,
      receivingChain: roleIsInitiator ? null : new ChainKey(chainKey),
      dhLocalPrivate: localDhPrivate,
      dhLocalPublic: localPub,
      dhRemotePublic: remoteDhPublic,
    });
  }

  private kdfRk(dhOut: Uint8Array): [Uint8Array, Uint8Array] {
    const okm = hkdfDerive(dhOut, this.rootKey, DH_RATCHET_INFO, 64);
    return [okm.slice(0, 32), okm.slice(32)];
  }

  private dhRatchetStep(): void {
    if (this.receivingChain) {
      this.previousCounter = this.receivingChain.index;
    }

    // Receive step: use EXISTING local key
    const existingLocal = X25519KeyPair.fromPrivateBytes(this.dhLocalPrivate!);
    const dhRecv = existingLocal.dh(this.dhRemotePublic!);
    const [rootRecv, recvChainKey] = this.kdfRk(dhRecv);
    this.rootKey = rootRecv;
    this.receivingChain = new ChainKey(recvChainKey);

    // Send step: generate new key pair
    const newLocal = X25519KeyPair.generate();
    this.dhLocalPrivate = newLocal.privateKey;
    this.dhLocalPublic = newLocal.publicKey;
    const dhSend = newLocal.dh(this.dhRemotePublic!);
    const [rootSend, sendChainKey] = this.kdfRk(dhSend);
    this.rootKey = rootSend;
    this.sendingChain = new ChainKey(sendChainKey);
  }

  private trySkippedMessageKey(dhPublic: Uint8Array, messageNumber: number): Uint8Array | null {
    const key = `${toHex(dhPublic)}:${messageNumber}`;
    const mk = this.skippedKeys.get(key);
    if (mk) {
      this.skippedKeys.delete(key);
      return mk;
    }
    return null;
  }

  private skipMessageKeys(until: number): void {
    if (!this.receivingChain) return;
    while (this.receivingChain!.index < until) {
      const result: [Uint8Array, ChainKey] | null = this.receivingChain!.nextMessageKey();
      if (!result) break;
      const mk: Uint8Array = result[0];
      const nextCk: ChainKey = result[1];
      const key = `${toHex(this.dhRemotePublic!)}:${this.receivingChain!.index}`;
      this.skippedKeys.set(key, mk);
      if (this.skippedKeys.size > this.maxSkip) {
        const oldest = this.skippedKeys.keys().next().value!;
        this.skippedKeys.delete(oldest);
      }
      this.receivingChain = nextCk;
    }
  }

  ratchetEncrypt(plaintext: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array {
    // If no sending chain, do DH ratchet to create one
    if (!this.sendingChain) {
      if (!this.dhRemotePublic) throw new Error('No remote DH public key');
      const newLocal = X25519KeyPair.generate();
      this.dhLocalPrivate = newLocal.privateKey;
      this.dhLocalPublic = newLocal.publicKey;
      const dhOut = newLocal.dh(this.dhRemotePublic);
      const [rootKey, sendChainKey] = this.kdfRk(dhOut);
      this.rootKey = rootKey;
      this.sendingChain = new ChainKey(sendChainKey);
    }

    const msgNum = this.sendingChain.index;
    const result = this.sendingChain.nextMessageKey();
    if (!result) throw new Error('Chain exhausted');
    const [messageKey, nextCk] = result;
    this.sendingChain = nextCk;
    this.messagesSent++;

    const header = concatBytes(this.dhLocalPublic!, packUint32LE(msgNum));
    const noncePrefix = randomBytesExport(8);
    const nonce = concatBytes(noncePrefix, packUint32LE(msgNum));
    const fullAd = concatBytes(associatedData, header);
    const encrypted = chacha20Poly1305Encrypt(messageKey, plaintext, fullAd, nonce);

    return concatBytes(header, encrypted);
  }

  ratchetDecrypt(ciphertext: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (ciphertext.length < KEY_LENGTH + 4 + NONCE_LENGTH + TAG_LENGTH) {
      throw new Error('Ciphertext too short');
    }

    const remoteDhPub = ciphertext.slice(0, KEY_LENGTH);
    const msgNum = unpackUint32LE(ciphertext, KEY_LENGTH);
    const encryptedPart = ciphertext.slice(KEY_LENGTH + 4);

    let mk = this.trySkippedMessageKey(remoteDhPub, msgNum);
    if (!mk) {
      if (!this.uint8ArrayEqual(remoteDhPub, this.dhRemotePublic)) {
        // New remote key: abandon old chain, do full DH ratchet
        this.receivingChain = null;
        this.skippedKeys.clear();
        this.dhRemotePublic = new Uint8Array(remoteDhPub);
        this.dhRatchetStep();
      }

      if (this.receivingChain) {
        this.skipMessageKeys(msgNum);
        const result = this.receivingChain.nextMessageKey();
        if (!result) throw new Error('Receiving chain exhausted');
        mk = result[0];
        this.receivingChain = result[1];
      } else {
        throw new Error('No receiving chain');
      }
    }

    const header = concatBytes(remoteDhPub, packUint32LE(msgNum));
    const fullAd = concatBytes(associatedData, header);

    return chacha20Poly1305Decrypt(mk, encryptedPart, fullAd);
  }

  private uint8ArrayEqual(a: Uint8Array | null, b: Uint8Array | null): boolean {
    if (!a || !b) return false;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
