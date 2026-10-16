# Threat Model - Sibna Protocol v3.0.2

## 1. Assets

The following assets are protected by the Sibna Protocol:

- **Message contents**: Plaintext application data exchanged between peers.
- **Identity keys**: Long-term Ed25519 identity keys used for authentication and key agreement.
- **Signed prekeys**: Medium-term X25519 prekeys used in X3DH handshakes.
- **One-time prekeys**: Single-use X25519 prekeys for forward secrecy.
- **Session keys**: Ephemeral Double Ratchet root keys, chain keys, and message keys.
- **Metadata**: Sender/recipient identity, message timing, and message size (partially protected by padding).
- **Stored state**: Persisted session state, keystore contents, and storage blobs on disk.

## 2. Adversary Model

The protocol is analyzed against a **Dolev-Yao** adversary with the following capabilities:

### Network-level adversary

- Can read, intercept, inject, delay, reorder, and drop messages on the relay or P2P transport layers.
- Can observe IP addresses, packet sizes, timing, and participant identities.
- Cannot break cryptographic primitives (X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256, BLAKE3, ML-KEM-768) assuming standard hardness assumptions hold.

### Session-level adversary

- Can compromise a specific session's ephemeral state (e.g., via memory access to a running client).
- Forward secrecy ensures past session keys cannot be recovered from a compromised ephemeral state.
- Break-in recovery ensures future sessions remain secure after the ratchet advances.

### Local adversary

- Can read files on disk (keystore, storage blobs, session state).
- Can read memory of a running process.
- Cannot break out of the sandbox or compromise the OS kernel.

## 3. Assumptions

- **Hardness assumptions**: Computational Diffie-Hellman (CDH) over Curve25519 and Module-LWE (FIPS 203) are hard for polynomial-time adversaries.
- **Randomness**: The operating system's CSPRNG (`os.urandom` / `getrandom`) provides sufficient entropy.
- **Key management**: Users verify safety numbers out-of-band to prevent man-in-the-middle attacks.
- **Trusted execution environment**: The code runs on a host not compromised at the kernel level.

## 4. Protections

| Asset | Protection Mechanism | Coverage |
|-------|---------------------|----------|
| Message contents | ChaCha20-Poly1305 AEAD encryption | Confidentiality + integrity |
| Identity keys | Ed25519 signatures | Authentication |
| Signed prekeys | Ed25519 signature over `SibnaSignedPreKey_v3` + SPK | Prekey authenticity |
| Session keys | Double Ratchet (HMAC-SHA256 symmetric + X25519 DH ratchet) | Forward secrecy + break-in recovery |
| Transcript binding | BLAKE3 + HKDF-SHA256 with `SibnaX3DH_TranscriptBind_v3` | Session binding |
| Post-quantum | ML-KEM-768 hybrid in X3DH (default ON) | Quantum resistance (if `pqc` feature enabled) |
| Metadata | Block-aligned padding with random prefix/suffix | Traffic analysis resistance (partial) |
| Identity verification | Safety numbers (SHA-512 fingerprint, 80 digits) | MITM detection (if verified out-of-band) |
| Stored state | Argon2id + ChaCha20-Poly1305 encryption, HMAC-authenticated manifest | At-rest protection (partial) |
| Replay protection | Time-bounded message number window | Replay attack mitigation |

## 5. Limitations and Unverified Claims

- **No independent audit**: The protocol and implementations have not undergone formal third-party cryptographic review.
- **No formal verification**: The protocol has not been verified with ProVerif, Tamarin, or equivalent tools.
- **No hardware side-channel resistance**: Resistance to differential power analysis (DPA), cache timing attacks, and similar hardware-level attacks is outside the design scope.
- **Kernel compromise**: A compromised host environment can bypass memory pinning, secure storage, and all software protections.
- **Traffic analysis**: Padding provides limited traffic analysis resistance; IP addresses, packet timing, and participant identities remain visible to the relay and network observers.
- **TOFU risk**: Until safety numbers are verified out-of-band, the protocol is vulnerable to active man-in-the-middle attacks.
- **Software-only key storage**: An attacker with persistent filesystem access can recover past key material from disk.

## 6. Residual Risks

The following risks remain after applying all protections:

1. **Man-in-the-middle before safety number verification**: TOFU applies until users verify safety numbers out-of-band.
2. **Local key theft**: Filesystem access to keystore or storage blobs can reveal past and current keys (protected only by Argon2id-derived encryption).
3. **Metadata leakage**: The relay observes sender, recipient, timing, and message size. Padding obscures content size but not communication patterns.
4. **Quantum attack on X25519-only sessions**: If `pqc` is disabled, a sufficiently powerful quantum computer breaks X25519 key agreement.
5. **Implementation bugs**: Cryptographic implementations may contain subtle bugs despite passing test suites.
