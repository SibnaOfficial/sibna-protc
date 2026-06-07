# Sibna Protocol — Python SDK

> **Sibna Protocol v3.0.1** — relay client with sealed-envelope messaging, identity management, and metadata-resistant padding.
> This document reflects the code that is actually shipped in this directory. Anything not listed below is not implemented in this SDK.

## What this SDK is

The Python SDK is a **pure-Python** client library for talking to a Sibna relay server. It is **not** a self-contained cryptography stack — it is a transport + envelope layer.

What is implemented in `sdks/python/sibna/`:

| Capability | Implemented? | Where |
|---|---|---|
| Ed25519 identity keypair generation | ✅ | `sibna.client.Identity` |
| Ed25519 sign / verify | ✅ | `Identity.sign`, `verify_signed_envelope` |
| Sealed-envelope message format (sign + payload) | ✅ | `make_signed_envelope`, `verify_signed_envelope` |
| Block-aligned payload padding (1 KiB blocks) | ✅ | `pad_payload`, `unpad_payload` |
| Sync HTTP client (REST) | ✅ | `SibnaClient` |
| Async WebSocket client | ✅ | `AsyncSibnaClient` |
| TLS certificate pinning (PEM file) | ✅ | `SibnaClient(pinned_cert=...)`, `AsyncSibnaClient(pinned_cert=...)` |
| Fan-out to multiple recipient devices | ✅ | `send_message_multi`, `send_multi` |
| Offline inbox polling with signature verification | ✅ | `fetch_inbox` |
| WebSocket ACK on received message | ✅ | inside `AsyncSibnaClient.connect` |

What is **not** implemented in this SDK:

- ❌ X3DH handshake — not present.
- ❌ Double Ratchet — not present.
- ❌ Group messaging / sender keys — not present.
- ❌ Safety number / verification QR — not present.
- ❌ ChaCha20-Poly1305 encryption helpers — the SDK signs the envelope and pads the payload, but it does **not** encrypt the application message. The encrypted payload (Double Ratchet ciphertext) is expected to be produced by a separate component (e.g. a Rust core) and passed in as `payload_hex`.

If you need end-to-end encrypted messaging, the Python SDK is the **envelope/transport layer**. Pair it with `sibna-core` for the cryptographic layer.

## Requirements

- Python 3.8+
- One of the following install profiles:
  - HTTP sync only: `cryptography`, `requests`
  - WebSocket async: `cryptography`, `aiohttp`

## Installation

```bash
# from this repository
cd sdks/python
pip install -r requirements.txt
pip install -e .
```

`requirements.txt` lists:

```
cryptography
requests
aiohttp
websockets
```

The package is not currently published to PyPI. Install it from the source tree.

## Module layout

```
sdks/python/
├── sibna/
│   ├── __init__.py        # FFI-style ctypes shim (optional, requires libsibna)
│   └── client.py          # Pure-Python client (this README documents this)
├── tests/
├── requirements.txt
└── setup.py
```

There are two entry points inside `sibna/`:

1. `sibna.client` — the pure-Python sealed-envelope client documented here.
2. `sibna` (the package root) — a ctypes shim around the native `libsibna` shared library. The shim is loaded only if the library is found on the system. It is **not** a complete client; it is a thin FFI wrapper for `sibna_context_*`, `sibna_session_*`, `sibna_identity_*` etc. Most of the methods are stubs that raise `NotImplementedError` because the corresponding native functions are not yet exported from the Rust core.

## Quick start (HTTP, sync)

```python
from sibna.client import SibnaClient, Identity

# 1. Create client
client = SibnaClient(server="https://sibna.example.com",
                     pinned_cert="/etc/sibna/server.pem")

# 2. Generate or load an Ed25519 identity
identity = client.generate_identity()
# or: identity = Identity.load("/path/to/private.key")
# or: identity = Identity(private_key_bytes=raw_32_bytes)

# 3. Authenticate against the server (Ed25519 challenge-response → JWT)
token = client.authenticate()   # returns the JWT string

# 4. Upload a PreKey bundle (bundle_hex is produced by the Rust core)
client.upload_prekey(bundle_hex="...", is_last_resort=False)

# 5. Send a sealed envelope to a recipient.
#    payload_hex is the already-encrypted ciphertext (e.g. Double Ratchet output).
status = client.send_message(
    recipient_id="<64-char Ed25519 public key hex>",
    payload_hex="<ciphertext as hex>",
    sign=True,
)

# 6. Poll the offline inbox
for envelope in client.fetch_inbox():
    print(envelope["message_id"], envelope["sender_id"])
```

## Quick start (WebSocket, async)

```python
import asyncio
from sibna.client import AsyncSibnaClient

async def main():
    client = AsyncSibnaClient(server="https://sibna.example.com",
                              pinned_cert="/etc/sibna/server.pem")
    client.generate_identity()
    await client.authenticate()

    async def on_message(envelope):
        print("got:", envelope["message_id"])

    await client.connect(on_message=on_message)
    # The connection stays open; send() uses the same JWT.
    await client.send(recipient_id="<hex>", payload_hex="<hex>")
    # keep alive ...
    # (the class is single-shot — closing the context manager ends the connection)

asyncio.run(main())
```

## API reference

### `class Identity`

Ed25519 keypair backed by `cryptography.hazmat`.

| Method / property | Description |
|---|---|
| `Identity(private_key_bytes=None)` | Generate a new keypair, or load one from a 32-byte raw seed. |
| `Identity.load(path)` | Load a 32-byte raw private key from a file. The file is created with mode `0o600`. |
| `i.save(path)` | Save the 32-byte raw private key to a file. |
| `i.public_key_bytes` | 32-byte raw Ed25519 public key. |
| `i.public_key_hex` | 64-character hex of the public key. |
| `i.private_key_bytes` | 32-byte raw Ed25519 private seed. |
| `i.sign(data)` → `bytes` | Returns a 64-byte Ed25519 signature. |
| `i.sign_hex(data)` → `str` | Hex-encoded signature. |

### Padding

```python
from sibna.client import pad_payload, unpad_payload

padded = pad_payload(b"hello")          # 1024-byte aligned, with random prefix and trailer
plain  = unpad_payload(padded)         # b"hello"
```

Wire format (matches the Rust core's padding block):

```
[ prefix_len(1) | prefix_noise(1..8) | plaintext | random_padding | pad_len(2, LE) ]
```

The output is always a multiple of 1024 bytes. A 0..1 extra block of random padding is added per call to make two paddings of the same plaintext indistinguishable in size.

### Sealed envelope

```python
from sibna.client import make_signed_envelope, verify_signed_envelope

env = make_signed_envelope(identity, recipient_id="<hex>", payload_hex="<hex>")
ok  = verify_signed_envelope(env)   # also rejects envelopes older than 5 minutes
```

Envelope fields:

| Field | Type | Notes |
|---|---|---|
| `recipient_id` | hex string | The server routes on this; the payload is opaque to the relay. |
| `payload_hex` | hex string | Encrypted application message. |
| `sender_id` | hex string | The sender's Ed25519 public key (32 bytes, hex). |
| `timestamp` | int | Unix seconds. Envelopes older than 5 minutes are rejected. |
| `message_id` | string | UUIDv4 random identifier. |
| `signature_hex` | hex string | Ed25519 signature over `SHA-512(recipient_id ‖ payload_hex ‖ timestamp ‖ message_id)`. |
| `compressed` | bool | Reserved flag, currently always `False`. |

### `class SibnaClient` (synchronous HTTP)

Constructor:

```python
SibnaClient(server: str = "http://localhost:8080", pinned_cert: str | None = None)
```

| Method | Description |
|---|---|
| `generate_identity(private_key_bytes=None) → Identity` | Generate or load a keypair; assigns to `self.identity`. |
| `authenticate() → str` | Full Ed25519 challenge-response, returns the JWT, also stored as `self.jwt_token`. JWT is valid for 24 h. |
| `health() → dict` | Returns the JSON body of `GET /health`. |
| `upload_prekey(bundle_hex, is_last_resort=False)` | `POST /v1/prekeys/upload`. The `bundle_hex` is opaque to the Python SDK — it is produced by the Rust core. |
| `fetch_prekeys(root_id_hex) → list[str]` | `GET /v1/prekeys/{root_id_hex}`. Returns a list of bundle hex strings, one per linked device. The server deletes them after fetch. |
| `send_message(recipient_id, payload_hex, sign=True, compress=False) → int` | `POST /v1/messages/send`. Returns the HTTP status (200 = live delivery, 202 = queued offline). |
| `send_message_multi(encrypted_messages, sign=True, compress=False) → dict[str, int]` | Fan-out to multiple devices; returns a per-recipient status map. |
| `fetch_inbox() → list[dict]` | `GET /v1/messages/inbox`. Returns envelopes whose signature verifies. Envelopes with invalid signatures are dropped and a warning is printed. |

Error mapping:

| HTTP status | Raised exception |
|---|---|
| 401 | `AuthError` |
| 429 | `NetworkError` (status_code=429) |
| any other ≥ 400 | `NetworkError` |

### `class AsyncSibnaClient` (asynchronous WebSocket)

Constructor:

```python
AsyncSibnaClient(server: str = "http://localhost:8080", pinned_cert: str | None = None)
```

| Method | Description |
|---|---|
| `generate_identity(private_key_bytes=None) → Identity` | Same as the sync client. |
| `await authenticate() → str` | Ed25519 challenge-response over HTTP using `aiohttp`. |
| `await connect(on_message=None)` | Opens the WebSocket. `on_message(envelope)` is called for each verified envelope. Sends an `{"type":"ack","message_id":...}` frame for every received message. |
| `await send(recipient_id, payload_hex, sign=True, compress=False)` | Send a sealed envelope over the WebSocket. |
| `await send_multi(encrypted_messages, sign=True, compress=False)` | Fan-out. Uses `asyncio.TaskGroup` on Python 3.11+, falls back to `asyncio.gather` otherwise. |

The `on_message` callback receives the parsed envelope after `verify_signed_envelope` succeeds. WebSocket traffic of `type="envelope"` is accepted; the `type="webrtc"` traffic is logged but not dispatched (no WebRTC peer connection is opened in this SDK).

### Exceptions

| Class | Cause |
|---|---|
| `SibnaError` | Base class. Has a `status_code` attribute. |
| `AuthError(SibnaError)` | 401 responses. |
| `NetworkError(SibnaError)` | 429, other HTTP errors, transport failures. |
| `CryptoError(SibnaError)` | Padding or signature failure. |

## Security notes

- **TLS pinning** is supported. Pass `pinned_cert="/path/to/server.pem"` to enforce a single certificate. Without it, the client falls back to the system trust store and prints a `UserWarning`.
- **Signature verification** is mandatory on the receive side — `fetch_inbox` drops envelopes with invalid or expired signatures.
- **Sealed envelopes** hide the sender's identity from the relay: the server only sees `recipient_id`, `payload_hex`, and the metadata envelope fields. The `sender_id` is **not** stripped; clients that need to hide the sender from the server must proxy the envelope through a third party.
- **Padding** is block-aligned and includes a random prefix. It is **not** a substitute for application-level encryption.
- The `secrets` module is used for all randomness (`secrets.token_bytes`, `secrets.randbelow`).

## Limitations

- The Python SDK is the **envelope and transport layer only**. It does not implement X3DH, Double Ratchet, or group messaging. For end-to-end encrypted messaging, use `sibna-core` (Rust) or the Java SDK and pass the resulting ciphertext as `payload_hex` to this client.
- The package root `sibna/__init__.py` exposes an FFI shim around `libsibna`. Most of its methods (`Session.encrypt`, `Session.decrypt`) currently raise `NotImplementedError` because the corresponding symbols are not exported by the Rust core at this version. The shim is present but not yet a working client.

## License

Apache-2.0 OR MIT
