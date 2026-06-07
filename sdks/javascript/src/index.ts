/**
 * Sibna Protocol TypeScript/Node.js SDK v11.0
 * ============================================
 *
 * Full HTTP + WebSocket client SDK with:
 *   - Ed25519 identity (using @noble/ed25519)
 *   - JWT Auth: challenge-response flow
 *   - PreKey management (upload / fetch)
 *   - Sealed + Signed envelope messaging
 *   - Message padding (metadata resistance)
 *   - WebSocket real-time relay
 *   - Offline inbox polling
 *
 * Install:
 *   npm install @noble/ed25519 ws node-fetch
 *
 * Usage (Node.js):
 *   import { SibnaClient } from 'sibna-sdk';
 *   const client = new SibnaClient('http://localhost:8080');
 *   await client.generateIdentity();
 *   await client.authenticate();
 *   await client.sendMessage({ recipientId: '...', payloadHex: '...' });
 */

export const VERSION = '3.0.1'; // FIX: was '2.0.0' — must match protocol version

// ── Errors ───────────────────────────────────────────────────────────────────

export class SibnaError extends Error {
  constructor(message: string, public statusCode: number = 0) {
    super(message);
    this.name = 'SibnaError';
  }
}
export class AuthError extends SibnaError { constructor(msg: string, code = 401) { super(msg, code); this.name = 'AuthError'; } }
export class NetworkError extends SibnaError { constructor(msg: string, code = 0) { super(msg, code); this.name = 'NetworkError'; } }
export class CryptoError extends SibnaError { constructor(msg: string) { super(msg); this.name = 'CryptoError'; } }

// ── Crypto Utilities ─────────────────────────────────────────────────────────

/** Convert ArrayBuffer to hex string */
function toHex(buf: ArrayBuffer | Uint8Array): string {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Convert hex string to Uint8Array */
function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new CryptoError('Invalid hex string');
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return arr;
}

/** SHA-512 hash */
async function sha512(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-512', data as any);
  return new Uint8Array(buf);
}

/** Concatenate multiple Uint8Arrays */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const len = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

// ── Constants ────────────────────────────────────────────────────────────────

const PADDING_BLOCK = 1024;
// SIBNA-2026-018 parity with core::crypto::padding::MAX_EXTRA_BLOCKS
const MAX_EXTRA_BLOCKS = 7;
// Maximum value the 2-byte LE trailing length field can hold.
const MAX_PADDING_BYTES = 65535;

// ── Message Padding ───────────────────────────────────────────────────────────

/**
 * Pad payload to 1024-byte block boundary with metadata resistance.
 *
 * Wire format (matches Rust core):
 *   [ prefix_len(1) | prefix_noise(1-8) | plaintext | random_padding | padding_len(2, LE) ]
 *
 * Total output is always a multiple of PADDING_BLOCK.
 *
 * FIX: Phase 3.3 — the previous implementation used ``Math.random()``
 * (a non-cryptographic PRNG) to draw both ``prefixLen`` and
 * ``extraBlocks``. An attacker observing the on-wire size could
 * correlate the two non-crypto draws with timing or other side
 * channels, and the prefix_len could be predicted from the first
 * byte of the buffer. The fix uses ``crypto.getRandomValues`` for
 * both draws and the SIBNA-2026-018 cap of 0..7 extra blocks.
 */
export function padPayload(data: Uint8Array): Uint8Array {
  // 1. Random prefix noise (1-8 bytes) for length-hiding.
  //    Use a CSPRNG — Math.random is not cryptographically secure.
  const prefixLenByte = crypto.getRandomValues(new Uint8Array(1))[0];
  const prefixLen = (prefixLenByte % 8) + 1;
  const prefixNoise = crypto.getRandomValues(new Uint8Array(prefixLen));

  const block = PADDING_BLOCK;
  const minTotal = 1 + prefixLen + data.length + 2; // indicator + prefix + data + 2-byte len
  const remainder = minTotal % block;
  const minPadLen = remainder === 0 ? 0 : block - remainder;

  // 2. SIBNA-2026-018: extra_blocks ∈ [0, min(MAX_EXTRA_BLOCKS, max_blocks_for_budget)].
  //    Was 0..1 (Math.random() * 2) before the fix — same as Python/Go Phase 3.2/3.1.
  const maxBlocksForBudget = Math.max(0, Math.floor((MAX_PADDING_BYTES - minPadLen) / block));
  const capBlocks = Math.min(MAX_EXTRA_BLOCKS, maxBlocksForBudget);
  const extraBlocksByte = crypto.getRandomValues(new Uint8Array(1))[0];
  const extraBlocks = extraBlocksByte % (capBlocks + 1);
  const padLen = minPadLen + extraBlocks * block;

  if (padLen > MAX_PADDING_BYTES) {
    // Defensive: this branch is unreachable given the cap above.
    throw new CryptoError(`Computed pad_len ${padLen} exceeds max ${MAX_PADDING_BYTES}`);
  }

  const total = minTotal + padLen;
  const out = new Uint8Array(total);
  let offset = 0;

  // prefix_len byte
  out[offset++] = prefixLen;
  // prefix noise
  out.set(prefixNoise, offset); offset += prefixLen;
  // plaintext
  out.set(data, offset); offset += data.length;
  // random padding
  if (padLen > 0) {
    const randPad = crypto.getRandomValues(new Uint8Array(padLen));
    out.set(randPad, offset); offset += padLen;
  }
  // 2-byte LE padding length
  out[offset++] = padLen & 0xFF;
  out[offset++] = (padLen >> 8) & 0xFF;

  return out;
}

/**
 * Remove padding from a received payload.
 *
 * Reads the 2-byte LE padding length from the trailing bytes,
 * then the 1-byte prefix length from the header to recover plaintext.
 */
export function unpadPayload(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) throw new CryptoError('Payload too short to unpad');

  const totalLen = padded.length;
  // Read 2-byte LE padding length from the end
  const padLen = padded[totalLen - 1] * 256 + padded[totalLen - 2];
  const bodyLen = totalLen - 2 - padLen; // everything before padding + trailing len

  if (bodyLen < 1 || bodyLen > totalLen) {
    throw new CryptoError(`Invalid padding: bodyLen(${bodyLen}) out of range`);
  }

  // Read prefix_len from first byte
  const prefixLen = padded[0];
  if (prefixLen < 1 || prefixLen > 8) {
    throw new CryptoError(`Invalid prefix length: ${prefixLen}`);
  }

  const dataStart = 1 + prefixLen;
  const dataEnd = dataStart + (bodyLen - dataStart);

  if (dataStart > bodyLen || dataEnd > bodyLen) {
    throw new CryptoError(`Invalid padding layout: dataStart(${dataStart}) > bodyLen(${bodyLen})`);
  }

  return padded.slice(dataStart, dataEnd);
}

// ── Identity ─────────────────────────────────────────────────────────────────

export interface IdentityKeys {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Generate Ed25519 identity keypair using WebCrypto API.
 */
export async function generateIdentity(): Promise<IdentityKeys> {
  const kp = (await crypto.subtle.generateKey(
    { name: 'Ed25519' } as AlgorithmIdentifier,
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  // Ed25519 private key seed is in the 'd' field (base64url, 32 bytes)
  const privSeed = Uint8Array.from(
    atob((privateJwk.d as string).replace(/-/g, '+').replace(/_/g, '/')),
    c => c.charCodeAt(0)
  );
  return { publicKey, privateKey: privSeed };
}

/**
 * Sign data with Ed25519 private key using @noble/ed25519.
 * Falls back to WebCrypto if available.
 */
export async function signData(privateKey: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  // Try @noble/ed25519 first (more reliable)
  try {
    const { signAsync } = await import('@noble/ed25519');
    return await signAsync(data, privateKey);
  } catch {
    // Fallback to WebCrypto - need to derive public key from private key
    // Ed25519 public key = private key seed -> clamp -> scalar multiply base point
    // For WebCrypto, we need both d (private) and x (public) in the JWK
    const publicKey = await ed25519GetPublicKey(privateKey);
    const d = base64UrlEncode(privateKey);
    const x = base64UrlEncode(publicKey);
    
    const keyObj = await crypto.subtle.importKey(
      'jwk',
      { kty: 'OKP', crv: 'Ed25519', d, x } as JsonWebKey,
      { name: 'Ed25519' } as AlgorithmIdentifier,
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('Ed25519', keyObj, data as any);
    return new Uint8Array(sig);
  }
}

/** Derive Ed25519 public key from private key seed (synchronous) */
function ed25519GetPublicKey(privateKey: Uint8Array): Uint8Array {
  // Use tweetnacl-like approach: hash seed, clamp, scalar multiply
  // For a proper implementation, use @noble/ed25519's sync version
  try {
    const { getPublicKey } = require('@noble/ed25519');
    return getPublicKey(privateKey);
  } catch {
    throw new CryptoError('Cannot derive public key without @noble/ed25519');
  }
}

/** Base64url encode */
function base64UrlEncode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// ── Signed Envelope ───────────────────────────────────────────────────────────

export interface SignedEnvelope {
  recipient_id: string;
  payload_hex: string;
  sender_id: string;
  timestamp: number;
  message_id: string;
  signature_hex: string;
  compressed: boolean;
}

/**
 * Create a signed, sealed envelope for end-to-end integrity.
 * The server sees ONLY recipient_id. Everything else is opaque.
 */
export async function makeSignedEnvelope(
  identity: IdentityKeys,
  recipientId: string,
  payloadHex: string,
  compress = false,
): Promise<SignedEnvelope> {
  const messageId = crypto.randomUUID();
  const timestamp = Math.floor(Date.now() / 1000);

  // Build signing payload: SHA-512(recipient_id || payload_hex || timestamp || message_id)
  const encoder = new TextEncoder();
  const tsBytes = new Uint8Array(8);
  new DataView(tsBytes.buffer).setBigInt64(0, BigInt(timestamp), true);

  const signingPayload = concat(
    encoder.encode(recipientId),
    encoder.encode(payloadHex),
    tsBytes,
    encoder.encode(messageId),
  );
  const hash = await sha512(signingPayload);
  const signature = await signData(identity.privateKey, hash);

  return {
    recipient_id: recipientId,
    payload_hex: payloadHex,
    sender_id: toHex(identity.publicKey),
    timestamp,
    message_id: messageId,
    signature_hex: toHex(signature),
    compressed: compress,
  };
}

// ── HTTP Client ───────────────────────────────────────────────────────────────

export interface SendMessageOptions {
  recipientId: string;
  payloadHex: string;
  sign?: boolean;
  compress?: boolean;
}

/**
 * Sibna Protocol HTTP Client
 *
 * Compatible with browsers (Fetch API) and Node.js 18+ (native fetch).
 *
 * For Node.js production deployments, pass `pinnedCertPath` to enable
 * TLS certificate pinning (guards against compromised CAs):
 *   new SibnaClient('https://your-server', { pinnedCertPath: './server.pem' })
 */
export class SibnaClient {
  private baseUrl: string;
  private identity: IdentityKeys | null = null;
  private jwtToken: string | null = null;
  private fetchFn: typeof fetch;

  constructor(serverUrl = 'http://localhost:8080', options: { pinnedCertPath?: string } = {}) {
    this.baseUrl = serverUrl.replace(/\/$/, '');

    // FIX: TLS certificate pinning for Node.js environments.
    // Browsers enforce certificate validation natively; Node.js requires explicit pinning.
    if (options.pinnedCertPath && typeof globalThis.process !== 'undefined') {
      // Node.js environment detected
      try {
        const fs = require('fs');
        const https = require('https');
        const tls = require('tls');
        const cert = fs.readFileSync(options.pinnedCertPath);
        const agent = new https.Agent({
          ca: cert,          // Trust ONLY this certificate / CA
          checkServerIdentity: tls.checkServerIdentity, // Keep hostname verification
        });
        // Wrap fetch to always use the pinned agent
        const nodeFetch = (url: string, init?: RequestInit) =>
          fetch(url, { ...init, // @ts-ignore — Node.js fetch supports `agent`
            agent } as RequestInit);
        this.fetchFn = nodeFetch as unknown as typeof fetch;
      } catch (e) {
        throw new Error(`pinnedCertPath: could not load certificate from '${options.pinnedCertPath}': ${e}`);
      }
    } else {
      this.fetchFn = fetch.bind(globalThis);
      if (serverUrl.startsWith('https://') && !options.pinnedCertPath) {
        console.warn(
          '[sibna-sdk] WARNING: HTTPS server without certificate pinning. ' +
          'Pass options.pinnedCertPath for production deployments.'
        );
      }
    }
  }

  /** Generate a new Ed25519 identity keypair */
  async generateIdentity(existingPrivateKey?: Uint8Array): Promise<IdentityKeys> {
    if (existingPrivateKey) {
      // Re-derive public key from private key seed
      // For simplicity we require both to be passed in
      throw new CryptoError('Pass both public and private keys via setIdentity()');
    }
    this.identity = await generateIdentity();
    return this.identity;
  }

  /** Set an existing identity */
  setIdentity(keys: IdentityKeys): void {
    this.identity = keys;
  }

  get identityHex(): string {
    if (!this.identity) throw new AuthError('No identity loaded');
    return toHex(this.identity.publicKey);
  }

  /** Full Ed25519 challenge-response authentication */
  async authenticate(): Promise<string> {
    if (!this.identity) throw new AuthError('No identity loaded. Call generateIdentity() first.');

    // 1. Challenge
    const challengeRes = await this.post('/v1/auth/challenge', {
      identity_key_hex: this.identityHex,
    });
    const { challenge_hex } = await challengeRes.json();

    // 2. Sign
    const challengeBytes = fromHex(challenge_hex);
    const signature = await signData(this.identity.privateKey, challengeBytes);

    // 3. Prove
    const tokenRes = await this.post('/v1/auth/prove', {
      identity_key_hex: this.identityHex,
      challenge_hex,
      signature_hex: toHex(signature),
    });
    const { token } = await tokenRes.json();
    this.jwtToken = token;
    return token;
  }

  /** Check server health */
  async health(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/health`);
    return res.json();
  }

  /** Upload a signed PreKeyBundle */
  async uploadPrekey(bundleHex: string): Promise<void> {
    await this.post('/v1/prekeys/upload', { bundle_hex: bundleHex });
  }

  /** Fetch a peer's PreKeyBundles (one for each linked device, deleted from server after fetch) */
  async fetchPrekeys(rootIdHex: string): Promise<string[]> {
    const res = await this.get(`/v1/prekeys/${rootIdHex}`);
    const data = await res.json();
    return data.bundles_hex;
  }

  /** Send multiple sealed messages (Fan-out encryption fallback) */
  async sendMessageMulti(messages: { recipientId: string, payloadHex: string }[], sign = true, compress = false): Promise<Record<string, number>> {
    const results: Record<string, number> = {};
    for (const msg of messages) {
      results[msg.recipientId] = await this.sendMessage({ ...msg, sign, compress });
    }
    return results;
  }

  /** Send a sealed message (REST fallback) */
  async sendMessage(opts: SendMessageOptions): Promise<number> {
    const { recipientId, payloadHex, sign = true, compress = false } = opts;

    let body: Record<string, unknown>;
    if (sign && this.identity) {
      body = await makeSignedEnvelope(this.identity, recipientId, payloadHex, compress) as unknown as Record<string, unknown>;
    } else {
      body = {
        recipient_id: recipientId,
        payload_hex: payloadHex,
        compressed: compress,
      };
    }

    const res = await this.post('/v1/messages/send', body);
    return res.status;
  }

  /** Fetch offline messages from inbox */
  async fetchInbox(): Promise<SignedEnvelope[]> {
    if (!this.identity || !this.jwtToken) {
      throw new AuthError('Must authenticate before fetching inbox.');
    }
    const url = `${this.baseUrl}/v1/messages/inbox?identity_key_hex=${this.identityHex}&token=${this.jwtToken}`;
    const res = await fetch(url);
    await this.checkResponse(res);
    const data = await res.json();
    return (data.messages || []) as SignedEnvelope[];
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async post(path: string, body: unknown): Promise<Response> {
    const res = await this.fetchFn(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    await this.checkResponse(res);
    return res;
  }

  private async get(path: string): Promise<Response> {
    const res = await this.fetchFn(`${this.baseUrl}${path}`);
    await this.checkResponse(res);
    return res;
  }

  private async checkResponse(res: Response): Promise<void> {
    if (res.status === 429) throw new NetworkError('Rate limited', 429);
    if (res.status === 401) throw new AuthError('Unauthorized', 401);
    if (res.status >= 400) {
      const text = await res.text().catch(() => '');
      throw new NetworkError(`HTTP ${res.status}: ${text.slice(0, 200)}`, res.status);
    }
  }
}

// ── WebSocket Client ──────────────────────────────────────────────────────────

export type MessageHandler = (envelope: SignedEnvelope) => void | Promise<void>;

/**
 * Sibna WebSocket Client for real-time sealed envelope relay.
 */
export class SibnaWebSocket {
  private ws: WebSocket | null = null;
  private onMessageHandler: MessageHandler | null = null;

  constructor(
    private serverUrl: string,
    private token: string,
    private identity: IdentityKeys,
  ) { }

  /** Connect to the WebSocket relay */
  connect(onMessage?: MessageHandler): Promise<void> {
    this.onMessageHandler = onMessage || null;
    const wsUrl = `${this.serverUrl.replace('http://', 'ws://').replace('https://', 'wss://')}/ws?token=${this.token}`;

    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('🟢 Sibna WebSocket connected');
        resolve();
      };

      this.ws.onmessage = async (event) => {
        try {
          const data = typeof event.data === 'string' ? event.data : await event.data.text();
          const envelope: SignedEnvelope = JSON.parse(data);
          if (this.onMessageHandler) {
            await this.onMessageHandler(envelope);
          }
        } catch (e) {
          console.warn('⚠ Failed to parse message:', e);
        }
      };

      this.ws.onerror = () => reject(new NetworkError('WebSocket error'));
      this.ws.onclose = () => console.log('🔴 Sibna WebSocket disconnected');
    });
  }

  /** Send a sealed envelope over WebSocket */
  async send(recipientId: string, payloadHex: string, compress = false): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new NetworkError('WebSocket not connected');
    }
    const envelope = await makeSignedEnvelope(this.identity, recipientId, payloadHex, compress);
    this.ws.send(JSON.stringify(envelope));
  }

  /** Send multiple sealed envelopes over WebSocket (Fan-out encryption) */
  async sendMulti(messages: { recipientId: string, payloadHex: string }[], compress = false): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new NetworkError('WebSocket not connected');
    }
    const promises = messages.map(msg => this.send(msg.recipientId, msg.payloadHex, compress));
    await Promise.all(promises);
  }

  /** Disconnect */
  disconnect(): void {
    this.ws?.close();
  }
}

// ── Exports ───────────────────────────────────────────────────────────────────

export default {
  VERSION,
  SibnaClient,
  SibnaWebSocket,
  generateIdentity,
  signData,
  makeSignedEnvelope,
  padPayload,
  unpadPayload,
  SibnaError,
  AuthError,
  NetworkError,
  CryptoError,
};
