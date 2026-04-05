# Protocol Specification

## 1. Key Agreement

The key agreement is based on Extended Triple Diffie-Hellman (X3DH). 

Key Definitions:
- Identity Key (IK): Long-term Ed25519/X25519 key pair
- Signed Prekey (SPK): Medium-term X25519 key pair signed by IK
- One-Time Prekey (OPK): Single-use X25519 key pair
- Ephemeral Key (EK): Single-session X25519 key pair

By default, the handshake merges two independent mechanisms:
1. X25519: Classical Diffie-Hellman
2. ML-KEM-768 (FIPS 203): Responder KEM encapsulation

Both resulting shared secrets are concatenated and passed through HKDF-SHA256 to derive the master session key. 

## 2. Session Management

Messages are encrypted using unique keys derived from a chain key. The chain key is updated via HMAC-SHA256 after every message, providing forward secrecy. A Diffie-Hellman ratchet is executed on every full round trip to provide post-compromise security. Message ordering and replay protection are enforced using strict atomic counter sequences.

## 3. Hybrid Routing

`HybridRouter` defaults to a P2P-first policy. It queries the local cache for active sessions and falls back to a WebSocket-based encrypted relay if a direct TCP connection cannot be established.

## 4. Sealed Sender

The central server routes envelopes without inspecting payload metadata. Envelopes are signed over the concatenated byte representation of the recipient ID, payload, timestamp, and metadata flags using Ed25519.

## 5. Message Padding

Encryption incorporates message padding. Standard block sizes are 256 B, 1 KB, 4 KB, and 16 KB. This design prevents observers from inferring payload contents based on raw byte length. 

## 6. Cryptographic Primitives

- Key Derivation: HKDF-SHA256
- Authenticated Encryption: ChaCha20-Poly1305
- Key Exchange: X25519 and ML-KEM-768
- Signatures: Ed25519
- Hash Functions: SHA-512 and SHA-256
- Randomness: OS-provided CSPRNG

## 7. Storage Authentication

The server handles client prekey upload challenges using an HMAC-SHA256 authenticated token. Challenges are strictly one-time-use.
