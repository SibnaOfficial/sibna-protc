/**
 * Sibna Protocol v3.0.1 — Group Messaging (JavaScript)
 */

import { hkdfDerive, chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from './crypto';
import { hmacSha256 } from './crypto';

const CHAIN_KEY_SEED = new Uint8Array([0x02]);
const MESSAGE_KEY_SEED = new Uint8Array([0x01]);
const MAX_CHAIN_MESSAGES = 4000;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Sender Key ──────────────────────────────────────────────────────────────

export class SenderKey {
  chainKey: Uint8Array;
  index: number;
  maxMessages: number;

  constructor(chainKey: Uint8Array, index = 0, maxMessages = MAX_CHAIN_MESSAGES) {
    this.chainKey = chainKey;
    this.index = index;
    this.maxMessages = maxMessages;
  }

  static derive(masterSecret: Uint8Array, chainId: Uint8Array): SenderKey {
    const derived = hkdfDerive(masterSecret, undefined, chainId, 32);
    return new SenderKey(derived);
  }

  nextMessageKey(): [Uint8Array, SenderKey] | null {
    if (this.index >= this.maxMessages) return null;
    const mk = hmacSha256(this.chainKey, MESSAGE_KEY_SEED);
    const nextCk = hmacSha256(this.chainKey, CHAIN_KEY_SEED);
    return [mk, new SenderKey(nextCk, this.index + 1, this.maxMessages)];
  }

  deriveMessageKeys(count: number): Uint8Array[] {
    const keys: Uint8Array[] = [];
    let ck = this.chainKey;
    for (let i = 0; i < count && this.index + i < this.maxMessages; i++) {
      const mk = hmacSha256(ck, MESSAGE_KEY_SEED);
      ck = hmacSha256(ck, CHAIN_KEY_SEED);
      keys.push(mk);
    }
    return keys;
  }

  fork(count: number): [Uint8Array[], SenderKey] {
    const keys = this.deriveMessageKeys(count);
    const nextCk = keys.reduce((ck) => hmacSha256(ck, CHAIN_KEY_SEED), this.chainKey);
    return [keys, new SenderKey(nextCk, this.index + count, this.maxMessages)];
  }
}

// ── Sender Key Message ──────────────────────────────────────────────────────

export class SenderKeyMessage {
  readonly senderId: Uint8Array;
  readonly chainId: Uint8Array;
  readonly chainIndex: number;
  readonly ciphertext: Uint8Array;
  readonly signature: Uint8Array;

  constructor(params: {
    senderId: Uint8Array;
    chainId: Uint8Array;
    chainIndex: number;
    ciphertext: Uint8Array;
    signature?: Uint8Array;
  }) {
    this.senderId = params.senderId;
    this.chainId = params.chainId;
    this.chainIndex = params.chainIndex;
    this.ciphertext = params.ciphertext;
    this.signature = params.signature ?? new Uint8Array(0);
  }

  encode(): Uint8Array {
    return new Uint8Array([
      ...this.senderId, ...this.chainId,
      ...new Uint8Array([this.chainIndex & 0xFF, (this.chainIndex >>> 8) & 0xFF]),
      ...this.signature, ...this.ciphertext,
    ]);
  }

  static decode(data: Uint8Array): SenderKeyMessage {
    if (data.length < 32 + 16 + 2 + 64 + 16) throw new Error('Message too short');
    return new SenderKeyMessage({
      senderId: data.slice(0, 32),
      chainId: data.slice(32, 48),
      chainIndex: data[48] | (data[49] << 8),
      signature: data.slice(50, 114),
      ciphertext: data.slice(114),
    });
  }
}

// ── Group Session ───────────────────────────────────────────────────────────

export interface GroupMember {
  deviceId: Uint8Array;
  identityKey: Uint8Array;
  verified: boolean;
  addedAt: Date;
}

export class GroupSession {
  private _chainId: Uint8Array;
  private _masterSecret: Uint8Array;
  private _members: Map<string, GroupMember>;
  private _memberChainKeys: Map<string, SenderKey>;
  private _memberChainKeyData: Map<string, Uint8Array>;
  private _rotationMessageCount: number;
  private _messageCount: number;
  private _groupId: string;

  constructor(params?: {
    chainId?: Uint8Array;
    masterSecret?: Uint8Array;
    members?: GroupMember[];
    rotationMessageCount?: number;
    groupId?: string;
  }) {
    this._chainId = params?.chainId ?? crypto.getRandomValues(new Uint8Array(16));
    this._masterSecret = params?.masterSecret ?? crypto.getRandomValues(new Uint8Array(32));
    this._members = new Map();
    this._memberChainKeys = new Map();
    this._memberChainKeyData = new Map();
    this._rotationMessageCount = params?.rotationMessageCount ?? 100;
    this._messageCount = 0;
    this._groupId = params?.groupId ?? crypto.randomUUID();

    for (const member of params?.members ?? []) {
      const id = toHex(member.deviceId);
      this._members.set(id, member);
    }
  }

  get groupId(): string { return this._groupId; }
  get chainId(): Uint8Array { return new Uint8Array(this._chainId); }
  get memberCount(): number { return this._members.size; }

  addMember(member: GroupMember): void {
    this._members.set(toHex(member.deviceId), member);
    this._deriveChainKey(member.deviceId);
  }

  removeMember(deviceId: Uint8Array): void {
    const id = toHex(deviceId);
    this._members.delete(id);
    this._memberChainKeys.delete(id);
    this._memberChainKeyData.delete(id);
  }

  getMemberChainKeys(): Map<string, Uint8Array> {
    return new Map(this._memberChainKeyData);
  }

  private _deriveChainKey(deviceId: Uint8Array): Uint8Array {
    const id = toHex(deviceId);
    const existing = this._memberChainKeyData.get(id);
    if (existing) return existing;
    const chainKey = hkdfDerive(this._masterSecret, undefined, deviceId, 32);
    const sk = new SenderKey(chainKey);
    this._memberChainKeys.set(id, sk);
    this._memberChainKeyData.set(id, chainKey);
    return chainKey;
  }

  rotate(): void {
    this._messageCount = 0;
  }

  encrypt(plaintext: Uint8Array): Uint8Array {
    const chainKey = this._deriveChainKey(this._chainId);
    const sk = new SenderKey(chainKey);
    const result = sk.nextMessageKey();
    if (!result) throw new Error('Chain exhausted');
    const [mk, nextCk] = result;

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = chacha20Poly1305Encrypt(mk, plaintext, this._chainId, nonce);

    const msg = new SenderKeyMessage({
      senderId: this._chainId,
      chainId: this._chainId,
      chainIndex: sk.index,
      ciphertext: ct,
    });

    this._messageCount++;
    this._memberChainKeys.set(toHex(this._chainId), nextCk);
    this._memberChainKeyData.set(toHex(this._chainId), nextCk.chainKey);

    if (this._messageCount >= this._rotationMessageCount) {
      this.rotate();
    }

    return msg.encode();
  }

  decrypt(messageData: Uint8Array, senderDeviceId: Uint8Array): Uint8Array {
    const msg = SenderKeyMessage.decode(messageData);
    const sk = new SenderKey(this._deriveChainKey(senderDeviceId));
    const keys = sk.deriveMessageKeys(msg.chainIndex + 1);
    if (msg.chainIndex >= keys.length) throw new Error('Cannot decrypt: chain too far behind');
    const mk = keys[msg.chainIndex];

    return chacha20Poly1305Decrypt(mk, msg.ciphertext, this._chainId);
  }

  generateMemberKey(member: GroupMember): Uint8Array {
    return hkdfDerive(this._masterSecret, undefined, member.deviceId, 32);
  }
}
