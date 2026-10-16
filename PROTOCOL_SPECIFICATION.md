# Sibna Protocol Specification - v3.0.2

---

## 1. Definitions

**MUST** — mandatory for security or interoperability.  
**SHOULD** — recommended, non-mandatory.  
**MAY** — optional.

---

## 2. Key Agreement: X3DH

### 2.1 Key Types

| Type | Algorithm | Lifespan |
|------|-----------|----------|
| Identity Key (IK) | Ed25519 + X25519 (dual-key) | Permanent |
| Signed Prekey (SPK) | X25519, signed by Ed25519 IK | ≤ 30 days |
| One-Time Prekey (OPK) | X25519 | Single use |
| Ephemeral Key (EK) | X25519 | Single handshake |
| Post-Quantum Key | ML-KEM-768 (FIPS 203) | Tied to SPK rotation |

### 2.2 SPK Signature

The initiator MUST verify the SPK signature before any DH computation:

```
spk_signature = Ed25519.Sign(IK_B.private, "SibnaSignedPreKey_v3" || SPK_B.public)
```

Bundles with an invalid SPK signature MUST be rejected.

### 2.3 Handshake Steps

```
Alice (Initiator)                           Bob (Responder)
─────────────────────────────────────────────────────────
1. Fetch prekey bundle; verify SPK signature against IK_B.
2. Generate random EK_A.
3. [PQC] (ss_kem, ct_kem) = ML-KEM-768.Enc(SPK_B.pq_pk)
4. Compute DH:
     dh1 = DH(IK_A.x25519, SPK_B)
     dh2 = DH(EK_A, IK_B.x25519)
     dh3 = DH(EK_A, SPK_B)
     dh4 = DH(EK_A, OPK_B)  [if present]
5. Transcript hash:
     T_internal = BLAKE3(IK_A || EK_A || IK_B || SPK_B || OPK_B ||
                          device_id_A || device_id_B)
     T = HKDF-SHA256-Extract(salt=transcript_hash_ext, ikm=T_internal)
         with info="SibnaX3DH_TranscriptBind_v3"
6. Derive session key:
     SK = HKDF-SHA256(salt=T, ikm=dh1 || dh2 || dh3 || dh4 || ss_kem)
```

`transcript_hash_ext` is `[0u8; 32]` for relay-mediated connections. For direct P2P it carries the P2P handshake transcript.

### 2.4 Associated Data

```
AD = IK_A.ed25519_public || IK_B.ed25519_public
```

---

## 3. Double Ratchet

### 3.1 Symmetric Ratchet

```
message_key[n]  = HMAC-SHA256(chain_key[n], 0x01)
chain_key[n+1]  = HMAC-SHA256(chain_key[n], 0x02)
```

`message_key` is zeroized immediately after use.

### 3.2 DH Ratchet

```
(root_key', chain_key') = HKDF-SHA256(
    salt = root_key,
    ikm  = DH(local_ratchet_key, remote_ratchet_key),
    info = "SibnaRatchet_v3",
    len  = 64,
)
```

### 3.3 Message Header

Wire layout (all fields little-endian):

```
nonce(12) || encrypted_header(56) || ciphertext(...)
```

The header is encrypted using a key derived from the sending chain key via `HMAC-SHA256(chain_key, 0x03)`. The plaintext header contains:

```
dh_public(32) || message_number(8) || previous_chain_length(8) || timestamp(8)
```

**Validation rules:**

- `dh_public` MUST NOT be all zeros.
- `message_number` MUST be ≤ 1 000 000 000 000.
- `timestamp` MUST be within [now − 86400s, now + 300s]. `timestamp == 0` is rejected.
- Header key is derived from the sending chain key using `HMAC-SHA256(chain_key, 0x03)`.

### 3.4 Skipped Message Keys

Up to `MAX_SKIPPED_MESSAGES = 2000` out-of-order message keys are cached. Each entry expires after 86 400 s. Skipped keys are single-use: removed on first use.

### 3.5 DH Key Persistence

The X25519 ratchet private scalar is never written to disk. `dh_local_serde` serializes `None` unconditionally. After a load, `dh_local` is `None`; the next outgoing ratchet step generates a fresh pair automatically.

### 3.6 Cover Traffic

Cover traffic provides traffic analysis resistance by sending encrypted dummy packets at exponentially distributed intervals (Poisson process). The mean delay is 5 seconds.

**Properties:**

- Dummy packets are encrypted with the same Double Ratchet as real messages.
- The recipient silently ignores packets that decrypt to empty plaintext.
- Each dummy packet is addressed to a random 32-byte recipient ID to prevent fingerprinting.
- The `is_dummy` field is included in the envelope signature to prevent forgery.
- Inter-packet delays follow an exponential distribution with configurable mean.

### 3.7 Key Rotation

Signed PreKeys (SPK) are rotated automatically based on `key_rotation_interval` (default: 86400 seconds / 24 hours). The rotation mechanism:

1. The keystore checks SPK age on each encrypt operation.
2. If age exceeds `key_rotation_interval`, a new SPK is generated and signed with the identity key.
3. The new SPK is uploaded to the relay server.
4. One-Time PreKeys (OPKs) are replenished when the count falls below a threshold.

---

## 4. Envelope Signing (Relay)

### 4.1 Canonical Signed Payload

```
canonical = u64_be(len(recipient_id)) || recipient_id_bytes
         || u64_be(len(message_id))   || message_id_bytes
         || u64_be(len(payload_hex))  || payload_hex_bytes
```

Length-prefix encoding prevents field-boundary reinterpretation. Concatenation without delimiters (used prior to v3.0.1) is invalid.

### 4.2 WebRTC Signals

Same format with fields: `recipient_id`, `payload_hex`.

---

## 5. Server Authentication

1. Client requests a 32-byte random challenge.
2. Server stores `HMAC-SHA256(challenge, jwt_secret)` with a TTL.
3. Client signs the raw challenge bytes with Ed25519.
4. Server verifies HMAC (constant-time) and Ed25519 signature, then issues JWT (HS256).

`SIBNA_JWT_SECRET` MUST be set in production (minimum 32 characters). The server returns an error on startup when `SIBNA_ENV=production` and the secret is absent or too short.

---

## 6. P2P Handshake

### 6.1 Peer Identity Verification

Set `P2pConfig::expected_peer_identity` to the peer's Ed25519 public key. The handshake rejects any peer whose identity does not match. This guards against active MITM substitution of the prekey bundle.

Leave this field `None` only for anonymous mDNS discovery. In that case, verify safety numbers interactively after connection.

### 6.2 Handshake Key Derivation

```
shared = X25519(our_ephemeral.private, peer_ephemeral.public)
K      = HKDF-SHA256(salt=shared, ikm=shared, info="SibnaHandshake_v3")
```

`K` encrypts `StealthBundle`, `StealthEnvelope`, and `OkSignal`. Each uses an independent random nonce.

---

## 7. Storage

### 7.1 File Layout

```
{db_path}           — Argon2id-encrypted payload (bincode 2, legacy wire format)
{db_path}.salt      — 32-byte Argon2id salt (header: b"SIBNA_SALT_V1")
{db_path}.manifest  — Rollback protection manifest
```

The salt file is written atomically on first `SecureContext::new` when a `db_path` is configured. An existing salt file is never overwritten.

### 7.2 Manifest

```
struct StorageManifest {
    version:         u32,
    sequence_number: u64,
    blob_hash:       [u8; 32],  // SHA-256(encrypted blob)
    manifest_mac:    [u8; 32],  // HMAC-SHA256(v||seq||hash, key=encryption_key)
}
```

On load, the HMAC is verified before the blob hash. A mismatch either indicates a rollback attempt or a manifest from v3.0.0 (which lacked HMAC). Delete the manifest to recover; rollback protection is inactive for that session.

**Threat model:** protects against an attacker who can write files but cannot derive the encryption key. Attackers with full memory access (cold boot, etc.) are out of scope.

---

## 8. Validation Limits

| Constant | Value |
|----------|-------|
| `MAX_AD_LEN` | 256 bytes |
| `MAX_MESSAGE_SIZE` | 10 MiB |
| `MAX_SESSION_ID_LEN` | 256 bytes |
| `MAX_PASSWORD_LEN` | 256 bytes |
| `MAX_SKIPPED_MESSAGES` | 2 000 |
| `MAX_MESSAGE_AGE_SECS` | 86 400 |
| `PROTOCOL_VERSION` (wire) | 10 |
| `MIN_COMPATIBLE_VERSION` | 9 |

---

## 9. Security Assumptions

| Component | Assumption |
|-----------|------------|
| X25519 | CDH over Curve25519 |
| ML-KEM-768 | Module-LWE (FIPS 203) |
| HKDF-SHA256 | PRF security |
| Ed25519 | EUF-CMA |
| ChaCha20-Poly1305 | IND-CCA2 |
| Argon2id | Memory-hard password KDF |

---

## 10. Known Limitations

**Software-only key storage.** Forward secrecy holds at the protocol layer. Key material on disk is protected by Argon2id + ChaCha20-Poly1305, but an attacker with persistent read access to the filesystem before key deletion can recover past material.

**No formal proof.** The protocol has not been verified with ProVerif, Tamarin, or equivalent tools.

**External audit pending.** The protocol has not received a formal external cryptographic audit.

---

## 11. Protocol Invariants

| Invariant | Where enforced |
|-----------|---------------|
| SPK signature verified before DH | `lib.rs::perform_handshake`, FFI path |
| X25519 private scalar never reaches disk | `dh_local_serde` |
| Replay detection uses time-bounded window | `encryptor::update_seen_numbers` |
| `timestamp == 0` rejected | `RatchetHeader::validate` |
| Envelope fields signed with length prefix | `server/ws.rs::route_message` |
| Manifest integrity via HMAC | `storage::load_context` |
| P2P peer identity verified | `p2p::initiator_handshake` |

---

## 12. Privacy Properties

| Property | Level | Notes |
|----------|-------|-------|
| Forward Secrecy | Full | Symmetric + DH ratchet |
| Post-Compromise Security | Full | DH ratchet round-trips |
| Identity Hiding | Partial | Relay sees sender for routing |
| Traffic Anonymity | Optional | SOCKS5/Tor via `P2pConfig::proxy` |
| Message Unlinkability | Full | Header encryption prevents session correlation |
