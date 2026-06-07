# Sibna Protocol — JavaScript / TypeScript SDK

> **Sibna Protocol v3.0.1** — relay client with sealed-envelope messaging, identity management, and metadata-resistant padding for Node.js 18+ and modern browsers.
> This document reflects the code that is actually shipped in `sdks/javascript/src/index.ts`. Anything not listed below is not implemented in this SDK.

## What this SDK is

The JavaScript SDK is a **transport + envelope** layer for talking to a Sibna relay server. It is **not** a self-contained end-to-end cryptography stack — the encrypted application message (e.g. Double Ratchet ciphertext) is expected to be produced by a separate component and passed in as a hex string.

What is implemented in `sdks/javascript/src/index.ts`:

| Capability | Implemented? | Notes |
|---|---|---|
| Ed25519 identity keypair generation | ✅ | Uses `crypto.subtle` (WebCrypto) when available, falls back to `@noble/ed25519`. |
| Ed25519 sign / verify | ✅ | `signData`, `SibnaClient.setIdentity`. |
| Sealed-envelope message format | ✅ | `makeSignedEnvelope`. |
| Block-aligned payload padding (1 KiB blocks) | ✅ | `padPayload`, `unpadPayload`. |
| HTTP client (REST) | ✅ | `SibnaClient` — works in browser and Node.js. |
| WebSocket client (real-time relay) | ✅ | `SibnaWebSocket` — uses the `WebSocket` global. |
| TLS certificate pinning (Node.js) | ✅ | `new SibnaClient(url, { pinnedCertPath: ... })` — only enforced in Node.js; browsers enforce certificate validation natively. |
| Fan-out to multiple recipients | ✅ | `sendMessageMulti`, `SibnaWebSocket.sendMulti`. |
| Offline inbox polling | ✅ | `fetchInbox`. |

What is **not** implemented:

- ❌ X3DH handshake — not present.
- ❌ Double Ratchet — not present.
- ❌ Group messaging / sender keys — not present.
- ❌ Safety number / verification QR — not present.
- ❌ Application-level encryption — the SDK signs the envelope and pads the payload, but does **not** encrypt the application message. The `payloadHex` you pass in must already be the encrypted ciphertext.

If you need end-to-end encrypted messaging, pair this SDK with `sibna-core` (Rust) or the Java SDK.

## Requirements

- Node.js 18+ (for `globalThis.fetch`, `crypto.subtle`, and `crypto.randomUUID`).
- Modern browser with WebCrypto support (Chrome / Edge / Firefox / Safari).
- Optional: `@noble/ed25519` for the most reliable Ed25519 path. The SDK falls back to WebCrypto Ed25519 if `@noble/ed25519` is not installed, but the WebCrypto fallback requires re-deriving the public key from the private seed, which is slower.

## Installation

```bash
cd sdks/javascript
npm install
npm run build      # tsc → dist/
```

The package is not currently published to npm. Use it from this source tree.

## Module layout

```
sdks/javascript/
├── src/
│   └── index.ts     # All public exports
├── tests/
│   └── (jest)
├── package.json
├── tsconfig.json
└── README.md
```

The public API is exported from `src/index.ts`:

- `VERSION: string`  — protocol version, always `"3.0.1"`.
- `SibnaClient`  — synchronous-style HTTP client (uses `fetch`).
- `SibnaWebSocket`  — WebSocket relay client.
- `generateIdentity(): Promise<IdentityKeys>`
- `signData(privateKey, data): Promise<Uint8Array>`
- `makeSignedEnvelope(identity, recipientId, payloadHex, compress?): Promise<SignedEnvelope>`
- `padPayload(data: Uint8Array): Uint8Array`
- `unpadPayload(padded: Uint8Array): Uint8Array`
- Error classes: `SibnaError`, `AuthError`, `NetworkError`, `CryptoError`.

## Quick start

```typescript
import { SibnaClient, VERSION } from 'sibna-protocol';

const client = new SibnaClient('https://sibna.example.com', {
  pinnedCertPath: './server.pem',   // Node.js only — browsers use the platform trust store
});

await client.generateIdentity();
const token = await client.authenticate();

await client.uploadPrekey('bundle-hex-from-rust-core');

const status = await client.sendMessage({
  recipientId: '...',
  payloadHex:  '...',   // already-encrypted ciphertext
  sign:        true,
});

// Poll the offline inbox
const inbox = await client.fetchInbox();
for (const env of inbox) {
  // env is a SignedEnvelope; senderId, messageId, signatureHex, etc.
}
```

## API reference

### `class SibnaClient`

Constructor:

```typescript
new SibnaClient(
  serverUrl?: string = 'http://localhost:8080',
  options?:  { pinnedCertPath?: string } = {}
)
```

If `serverUrl` starts with `https://` and `pinnedCertPath` is omitted, a warning is printed in Node.js (browsers ignore this — they always validate certificates via the platform).

| Method | Description |
|---|---|
| `generateIdentity(existingPrivateKey?)` | WebCrypto-backed Ed25519 keypair. `existingPrivateKey` is not yet supported; use `setIdentity()` instead. |
| `setIdentity(keys)` | Inject a keypair you generated yourself. |
| `identityHex` | Hex of the loaded identity's public key. Throws if no identity. |
| `authenticate()` | Ed25519 challenge-response → JWT. Stores token on the client. |
| `health()` | `GET /health` JSON. |
| `uploadPrekey(bundleHex)` | `POST /v1/prekeys/upload`. The bundle is opaque to this SDK. |
| `fetchPrekeys(rootIdHex)` | `GET /v1/prekeys/{rootIdHex}`. Returns an array of `string` (one per device). The server deletes them after fetch. |
| `sendMessage({ recipientId, payloadHex, sign?, compress? })` | `POST /v1/messages/send`. Returns the HTTP status (200 = live, 202 = queued). |
| `sendMessageMulti(messages, sign?, compress?)` | Fan-out. Returns `Record<recipientId, status>`. |
| `fetchInbox()` | `GET /v1/messages/inbox?identity_key_hex=…&token=…`. Returns an array of `SignedEnvelope` (signature verification is **not** performed in the HTTP client; verify them yourself with `verifySignedEnvelope` if you need that guarantee — the WebSocket client verifies automatically). |

### `class SibnaWebSocket`

```typescript
new SibnaWebSocket(
  serverUrl: string,
  token:     string,
  identity:  IdentityKeys,
)
```

| Method | Description |
|---|---|
| `connect(onMessage?)` | Open the WebSocket. `onMessage(envelope)` is called for each message. The current implementation does **not** verify the envelope's signature before dispatch — verify envelopes with `verifySignedEnvelope` inside your handler. |
| `send(recipientId, payloadHex, compress?)` | Send a sealed envelope (always signed). |
| `sendMulti(messages, compress?)` | Fan-out via `Promise.all`. |
| `disconnect()` | Close the WebSocket. |

### Padding

```typescript
import { padPayload, unpadPayload } from 'sibna-protocol';

const padded = padPayload(new TextEncoder().encode('hello'));
const plain  = unpadPayload(padded);
```

Wire format (matches the Rust core's padding block):

```
[ prefix_len(1) | prefix_noise(1..8) | plaintext | random_padding | pad_len(2, LE) ]
```

The output is always a multiple of 1024 bytes.

### Sealed envelope

```typescript
import { makeSignedEnvelope } from 'sibna-protocol';

const env = await makeSignedEnvelope(identity, '<recipient-hex>', '<payload-hex>');
```

Envelope fields (all snake-case in the wire format):

| Field | Type | Notes |
|---|---|---|
| `recipient_id` | hex string | Routed by the server; the payload is opaque. |
| `payload_hex` | hex string | The encrypted application message. |
| `sender_id` | hex string | The sender's Ed25519 public key. |
| `timestamp` | number | Unix seconds. |
| `message_id` | string | UUIDv4. |
| `signature_hex` | hex string | Ed25519 over `SHA-512(recipient_id ‖ payload_hex ‖ timestamp ‖ message_id)`. |
| `compressed` | boolean | Reserved. |

### Errors

| Class | HTTP status |
|---|---|
| `AuthError` | 401 |
| `NetworkError` | 429, other transport errors |
| `SibnaError` | base class |

`SibnaError` has a `statusCode` property (default 0).

## Security notes

- **TLS pinning** is supported on Node.js via `pinnedCertPath`. The pinned certificate is used as the only trust anchor for the connection. Browsers ignore this option (the platform validates the certificate).
- **Signature verification**: `SibnaClient.fetchInbox()` does not currently verify signatures — verify each envelope before processing it. The `SibnaWebSocket` class also does not verify by default in this revision; verify inside the `onMessage` callback.
- **Randomness** comes from `crypto.getRandomValues` and `crypto.randomUUID` — both use the platform CSPRNG.
- **Sealed envelopes** hide the application payload from the relay, but the `sender_id` is sent in clear. To hide the sender from the server, route envelopes through a trusted third party.
- **Padding** is block-aligned and includes a random prefix. It is not a substitute for encryption.

## Limitations

- The JavaScript SDK is the **envelope and transport layer only**. It does not implement X3DH, Double Ratchet, or group messaging. Use `sibna-core` or the Java SDK for the cryptographic layer.
- The `SibnaClient.fetchInbox()` and `SibnaWebSocket` paths return envelopes without verifying their signatures. Verify them in your application code before processing.
- The package is not currently published to npm.

## License

Apache-2.0 OR MIT
