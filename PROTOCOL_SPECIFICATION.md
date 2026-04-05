# Sibna Protocol Specification (v2.0.0 "Fortress")

This document detail the technical specification for the Sibna Protocol, covering key agreement, session management, and routing primitives.

## 1. Key Agreement (X3DH v10)

The key agreement is an Extended Triple Diffie-Hellman (X3DH) implementation, augmented with hybrid post-quantum key encapsulation (KEM) and transcript binding.

### Handshake Stages
1. **Initiation**: The initiator (Alice) fetches the responder's (Bob) prekey bundle, containing a Signed Prekey (SPK) and an optional One-Time Prekey (OPK).
2. **KEM Encapsulation**: Alice generates an ephemeral key pair (EK) and performs ML-KEM-768 encapsulation against Bob's SPK public key, yielding a shared secret `ss_kem`.
3. **Classical DH**: Alice performs the standard X25519 DH exchanges:
    - `dh1 = DH(IK_A, SPK_B)`
    - `dh2 = DH(EK_A, IK_B)`
    - `dh3 = DH(EK_A, SPK_B)`
    - `dh4 = DH(EK_A, OPK_B)` (if available)
4. **Transcript Hashing**: A BLAKE3 hash is computed over the concatenation of all public keys involved in the exchange: `transcript_hash = BLAKE3(IK_A || IK_B || EK_A || SPK_B || OPK_B || device_id_A || device_id_B)`.
5. **KDF Derivation**: The final master shared secret is derived via HKDF-SHA256:
    - `SK = HKDF(salt=transcript_hash, info="sibna_v10", ikm=ss_kem || dh1 || dh2 || dh3 || dh4)`

### Stealth Mode (Identity Obfuscation)
In Stealth Mode, the initiator identity key `IK_A` and any associated device metadata are encrypted using a transient "Stealth Envelope" derived from the initial ephemeral exchange. This ensures that a passive network observer cannot determine the communicating identities beyond the pre-established server-stored prekeys.

## 2. Session Management (Double Ratchet)

Messages are protected using a Double Ratchet mechanism, combining a symmetric-key chain ratchet and a Diffie-Hellman-based re-keying ratchet.

### Chain Ratchet
- **Encryption**: Every message increments the chain index. The current `chain_key` produces a `message_key` and the next `chain_key` via HMAC-SHA256.
- **Forward Secrecy**: Once a `message_key` is used, it is zeroized. The `chain_key` cannot be reversed to recover previous keys.

### DH Ratchet
- **Post-Compromise Security**: A full X25519 DH exchange is performed on every message round-trip. This "ratchets" the root key, ensuring that even if a session participant is compromised, secrecy is restored as soon as a subsequent successful exchange occurs.

## 3. Wire Format & Routing

### Sealed Sender
Sibna utilizes a "Sealed Sender" envelope design. The central relay server routes messages based on a 256-bit destination address without visibility into the sender's identity key or the message payload. Envelopes are authenticated via Ed25519 signatures over the encrypted payload and metadata.

### Message Padding
To prevent traffic analysis via payload length, all messages are padded to the nearest power-of-2 block size (256 B, 1 KB, 4 KB, or 16 KB) before encryption.

## 4. Cryptographic Primitives

| Primitives | Technical Selection |
| :--- | :--- |
| **Key Exchange** | X25519 (classical) & ML-KEM-768 (quantum) |
| **Encryption** | ChaCha20-Poly1305 (AEAD) |
| **KDF** | HKDF-SHA256 |
| **Signatures** | Ed25519 |
| **Password Hashing** | Argon2id |
| **Transcript Hash** | BLAKE3 |

## 5. Persistence & Storage

State persistence mandates an atomic `StorageManifest` check. Every state transition increments a monotonic sequence counter linked to the master storage key, preventing unauthorized state rollback or splicing attacks.
