# Protocol Specification — Sibna Protocol v1.0.4

## 1. Key Agreement: X3DH

### 1.1 Key Types
- **Identity Key (IK):** Ed25519 / X25519 (Permanent)
- **Signed Prekey (SPK):** X25519 signed by IK (Medium-term)
- **One-Time Prekey (OPK):** X25519 (Single-use)
- **Ephemeral Key (EK):** X25519 (Single-session)

### 1.2 Key Derivation
The shared secret is derived from up to four Diffie-Hellman operations (DH1–DH4) combined via HKDF-SHA256 with specific versioned info constants.

### 1.3 Post-Quantum Hybrid (Default)
By default, the handshake merges two independent mechanisms:
1. **X25519**: Classical Diffie-Hellman
2. **ML-KEM-768** (FIPS 203): Responder KEM encapsulation.

Both secrets are concatenated and passed through HKDF. An adversary must break both algorithms simultaneously to compromise the session.

## 2. Session Management: Double Ratchet

Messages are encrypted using unique keys derived from a chain key updated via HMAC-SHA256 after every message (Forward Secrecy). A Diffie-Hellman ratchet is executed on every full round trip to provide Post-Compromise Security.

## 3. Hybrid Routing

`HybridRouter` defaults to a P2P-first policy, querying active sessions and gracefully falling back to a WebSocket encrypted relay if a direct connection cannot be established or drops.

## 4. Sealed Sender
The server routes sealed envelopes without knowing the sender's identity. Envelopes are Ed25519-signed over `SHA-512(recipient_id ∥ payload ∥ timestamp ∥ message_id ∥ is_dummy)`, guaranteeing metadata binding.

## 5. Padding
Message padding is implemented using standard block sizes: `None`, `Small` (256 B), `Standard` (1 KB), `Large` (4 KB), and `Maximum` (16 KB) to prevent length analysis.

## 6. Cryptographic Parameters

| Parameter | Algorithm |
|-----------|-----------|
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| Key Exchange | X25519 (+ ML-KEM-768) |
| Signature | Ed25519 |
| Post-Quantum KEM | ML-KEM-768 (FIPS 203) |
| Hash | SHA-512 / SHA-256 |
