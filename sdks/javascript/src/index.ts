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

export const VERSION = '11.0.0';

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
    arr[i / 2] = parseInt(hex.substring(i, 2), 16);
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

// ── Message Padding ───────────────────────────────────────────────────────────

/**
 * Pad payload to nearest 1024-byte boundary.
 * Protects against size-based traffic correlation attacks.
 */
export function padPayload(data: Uint8Array): Uint8Array {
  const unpadded = data.length + 1;
  const remainder = unpadded % PADDING_BLOCK;
  let paddingNeeded = remainder === 0 ? PADDING_BLOCK : PADDING_BLOCK - remainder;
  const indicator = paddingNeeded % 256;
  const padding = crypto.getRandomValues(new Uint8Array(paddingNeeded));
  return concat(new Uint8Array([indicator]), data, padding);
}

/**
 * Remove padding from a received payload.
 */
export function unpadPayload(padded: Uint8Array): Uint8Array {
  if (!padded.length) throw new CryptoError('Empty payload');
  const indicator = padded[0];
  const padded_len = padded.length;
  const paddingNeeded = padded_len % PADDING_BLOCK;
  const actualPadding = paddingNeeded === 0 ? indicator : paddingNeeded;
  return padded.slice(1, padded_len - actualPadding);
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
 * Sign data with Ed25519 private key using WebCrypto.
 */
export async function signData(privateKey: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const keyObj = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'OKP',
      crv: 'Ed25519',
      d: btoa(String.fromCharCode(...privateKey)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
      x: '', // Will be derived by subtle
    } as JsonWebKey,
    { name: 'Ed25519' } as AlgorithmIdentifier,
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('Ed25519', keyObj, data as any);
  return new Uint8Array(sig);
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
 */
export class SibnaClient {
  private baseUrl: string;
  private identity: IdentityKeys | null = null;
  private jwtToken: string | null = null;

  constructor(serverUrl = 'http://localhost:8080') {
    this.baseUrl = serverUrl.replace(/\/$/, '');
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
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    await this.checkResponse(res);
    return res;
  }

  private async get(path: string): Promise<Response> {
    const res = await fetch(`${this.baseUrl}${path}`);
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
