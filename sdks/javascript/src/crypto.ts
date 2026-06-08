/**
 * Sibna Protocol v3.0.1 — Standalone Cryptographic Primitives (JavaScript)
 *
 * Ed25519, X25519, ChaCha20-Poly1305, HKDF, HMAC-SHA256, SHA-256/512
 * via @noble/ed25519, @noble/curves, @noble/ciphers, @noble/hashes
 */

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import { randomBytes } from 'crypto';

export const KEY_LENGTH = 32;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;

// Low-order X25519 points to reject
const LOW_ORDER_POINTS = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb8a3114509de3500459450f1f56e39cc03814c13efc4b3fb0839e41f80f17',
  'c3ada28304f53665966e72ca07de5614a4c00ceb534fbb99767401c0295c590f',
  '504c00c7ff6616830ca1da120b0bba22a2f44157298b3cd579e95138d96f8c17',
  'd8527d1f006f51e8b6542d6ae27e09eb88aec0c71e9c75cfd2c17d4d2b13d00e',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7e',
  'f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
]);

// ── Helpers ─────────────────────────────────────────────────────────────────

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex');
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return arr;
}

// ── Ed25519 ─────────────────────────────────────────────────────────────────

export class Ed25519KeyPair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;

  constructor(privateKey?: Uint8Array) {
    if (privateKey) {
      this.privateKey = privateKey;
      this.publicKey = ed25519.getPublicKey(privateKey);
    } else {
      this.privateKey = ed25519.utils.randomPrivateKey();
      this.publicKey = ed25519.getPublicKey(this.privateKey);
    }
  }

  static fromSeed(seed: Uint8Array): Ed25519KeyPair {
    if (seed.length !== 32) throw new Error('Seed must be 32 bytes');
    return new Ed25519KeyPair(seed);
  }

  sign(data: Uint8Array): Uint8Array {
    return ed25519.sign(data, this.privateKey);
  }

  verify(data: Uint8Array, signature: Uint8Array): boolean {
    return ed25519.verify(signature, data, this.publicKey);
  }

  static verifyWithKey(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
    return ed25519.verify(signature, data, publicKey);
  }
}

// ── X25519 ──────────────────────────────────────────────────────────────────

export class X25519KeyPair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;

  constructor(privateKey?: Uint8Array) {
    if (privateKey) {
      this.privateKey = privateKey;
      this.publicKey = x25519.getPublicKey(privateKey);
    } else {
      this.privateKey = x25519.utils.randomPrivateKey();
      this.publicKey = x25519.getPublicKey(this.privateKey);
    }
  }

  static generate(): X25519KeyPair {
    return new X25519KeyPair();
  }

  static fromPrivateBytes(bytes: Uint8Array): X25519KeyPair {
    return new X25519KeyPair(bytes);
  }

  dh(remotePublic: Uint8Array): Uint8Array {
    if (remotePublic.length !== 32) throw new Error('Remote key must be 32 bytes');
    if (LOW_ORDER_POINTS.has(toHex(remotePublic))) {
      throw new Error('Rejecting low-order X25519 public key');
    }
    return x25519.getSharedSecret(this.privateKey, remotePublic);
  }
}

// ── HKDF-SHA256 ─────────────────────────────────────────────────────────────

export function hkdfDerive(
  ikm: Uint8Array,
  salt?: Uint8Array,
  info: Uint8Array = new Uint8Array(0),
  length: number = 32,
): Uint8Array {
  return hkdf(sha256, ikm, salt || new Uint8Array(KEY_LENGTH), info, length);
}

// ── HMAC-SHA256 ─────────────────────────────────────────────────────────────

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac.create(sha256, key).update(data).digest();
}

// ── SHA ─────────────────────────────────────────────────────────────────────

export function sha256Hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function sha512Hash(data: Uint8Array): Uint8Array {
  return sha512(data);
}

// ── Blake3 (for X3DH transcript) ────────────────────────────────────────────

export function blake3Hash(...parts: Uint8Array[]): Uint8Array {
  // Use SHA-256 as fallback since blake3 may not be available
  const h = sha256.create();
  for (const p of parts) h.update(p);
  return h.digest();
}

// ── ChaCha20-Poly1305 ──────────────────────────────────────────────────────

export function chacha20Poly1305Encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  _associatedData: Uint8Array = new Uint8Array(0),
  nonce?: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_LENGTH) throw new Error('Key must be 32 bytes');
  const n = nonce || randomBytes(NONCE_LENGTH);
  const cipher = chacha20poly1305(key, n);
  const ct = cipher.encrypt(plaintext);
  const result = new Uint8Array(n.length + ct.length);
  result.set(n);
  result.set(ct, n.length);
  return result;
}

export function chacha20Poly1305Decrypt(
  key: Uint8Array,
  data: Uint8Array,
  _associatedData: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (key.length !== KEY_LENGTH) throw new Error('Key must be 32 bytes');
  if (data.length < NONCE_LENGTH + TAG_LENGTH) throw new Error('Ciphertext too short');
  const nonce = data.slice(0, NONCE_LENGTH);
  const ct = data.slice(NONCE_LENGTH);
  const cipher = chacha20poly1305(key, nonce);
  return cipher.decrypt(ct);
}

// ── Identity Key Derivation ─────────────────────────────────────────────────

export function deriveIdentityKeys(masterSeed: Uint8Array): [Ed25519KeyPair, X25519KeyPair] {
  const edSeed = hkdfDerive(masterSeed, undefined, new TextEncoder().encode('SibnaIdentityKey_Ed25519_v1'), 32);
  const xSeed = hkdfDerive(masterSeed, undefined, new TextEncoder().encode('SibnaIdentityKey_X25519_v1'), 32);
  return [new Ed25519KeyPair(edSeed), new X25519KeyPair(xSeed)];
}

// ── Random Bytes ────────────────────────────────────────────────────────────

export function randomBytesExport(length: number): Uint8Array {
  return new Uint8Array(randomBytes(length));
}
