/**
 * Sibna Protocol JavaScript/TypeScript SDK — Unit Tests
 */

import {
  VERSION,
  padPayload,
  unpadPayload,
  generateIdentity,
  SibnaError,
  AuthError,
  NetworkError,
  CryptoError,
} from '../src/index';

describe('VERSION', () => {
  it('should be 3.0.1', () => {
    expect(VERSION).toBe('3.0.1');
  });
});

describe('Padding', () => {
  it('should pad and unpad roundtrip', () => {
    const data = new TextEncoder().encode('Hello, World!');
    const padded = padPayload(data);
    expect(padded.length % 1024).toBe(0);
    const unpadded = unpadPayload(padded);
    expect(unpadded).toEqual(data);
  });

  it('should pad empty data', () => {
    const data = new Uint8Array(0);
    const padded = padPayload(data);
    expect(padded.length % 1024).toBe(0);
    const unpadded = unpadPayload(padded);
    expect(unpadded).toEqual(data);
  });

  it('should pad large data', () => {
    const data = new Uint8Array(5000).fill(0x42);
    const padded = padPayload(data);
    expect(padded.length % 1024).toBe(0);
    const unpadded = unpadPayload(padded);
    expect(unpadded).toEqual(data);
  });

  it('should throw on empty unpad', () => {
    expect(() => unpadPayload(new Uint8Array(0))).toThrow(CryptoError);
  });

  // FIX: Phase 3.3 — SIBNA-2026-018 parity with the Rust core.
  // extra_blocks is drawn uniformly from 0..7, so two messages of
  // identical plaintext length do not necessarily produce the same
  // on-wire size.
  it('padding size is not constant across trials (SIBNA-2026-018)', () => {
    const msg = new TextEncoder().encode('constant-size message');
    const sizes = new Set<number>();
    for (let i = 0; i < 64; i++) {
      const padded = padPayload(msg);
      expect(padded.length % 1024).toBe(0);
      sizes.add(padded.length);
    }
    expect(sizes.size).toBeGreaterThanOrEqual(2);
  });

  // FIX: Phase 3.3 — prefix_len must be in [1, 8] on every call.
  it('prefix_len is in [1, 8] on every call', () => {
    for (let i = 0; i < 32; i++) {
      const padded = padPayload(new TextEncoder().encode('ping'));
      const pl = padded[0];
      expect(pl).toBeGreaterThanOrEqual(1);
      expect(pl).toBeLessThanOrEqual(8);
    }
  });

  // FIX: Phase 3.3 — hand-built Rust-shaped buffer must unpad correctly.
  // Layout: [ 0x03 | 0xAA 0xBB 0xCC | "hello" | 1013 zero bytes | 0xF5 0x03 ]
  // where 0xF5 0x03 is little-endian pad_len=1013 (0x03F5).
  it('unpads Rust-shaped wire format', () => {
    const padLen = 1013;
    const buf = new Uint8Array(1024);
    buf[0] = 0x03;
    buf.set([0xAA, 0xBB, 0xCC], 1);
    buf.set(new TextEncoder().encode('hello'), 4);
    // pad bytes already 0
    buf[1022] = padLen & 0xFF;
    buf[1023] = (padLen >> 8) & 0xFF;
    expect(buf.length).toBe(1024);
    expect(unpadPayload(buf)).toEqual(new TextEncoder().encode('hello'));
  });
});

describe('Errors', () => {
  it('SibnaError should have statusCode', () => {
    const err = new SibnaError('test', 400);
    expect(err.message).toBe('test');
    expect(err.statusCode).toBe(400);
  });

  it('AuthError should have name', () => {
    const err = new AuthError('auth failed', 401);
    expect(err.name).toBe('AuthError');
    expect(err.statusCode).toBe(401);
  });

  it('NetworkError should have name', () => {
    const err = new NetworkError('network failed', 503);
    expect(err.name).toBe('NetworkError');
    expect(err.statusCode).toBe(503);
  });

  it('CryptoError should have name', () => {
    const err = new CryptoError('crypto failed');
    expect(err.name).toBe('CryptoError');
  });
});

describe('Identity', () => {
  it('should generate identity', async () => {
    const identity = await generateIdentity();
    expect(identity.publicKey).toBeInstanceOf(Uint8Array);
    expect(identity.privateKey).toBeInstanceOf(Uint8Array);
    expect(identity.publicKey.length).toBe(32);
    expect(identity.privateKey.length).toBe(32);
  });

  it('should generate unique identities', async () => {
    const id1 = await generateIdentity();
    const id2 = await generateIdentity();
    expect(id1.publicKey).not.toEqual(id2.publicKey);
  });
});
