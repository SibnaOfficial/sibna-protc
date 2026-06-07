# Sibna Protocol — Java SDK

> **Sibna Protocol v3.0.1** — pure-Java implementation of X3DH handshake, Double Ratchet, sender-key group messaging, and HTTP relay transport.
> This document reflects the code that is actually shipped in `sdks/java/`. Anything not listed below is not implemented in this SDK.

## What this SDK is

The Java SDK is the **only multi-language SDK in this repository that includes a full end-to-end cryptography stack**. It is pure Java 17+ with no native dependencies — all primitives come from the JDK (`EdDSA`, `XDH`, `ChaCha20-Poly1305`, `HmacSHA256`, `SecureRandom`).

What is implemented in `sdks/java/src/main/java/com/sibna/`:

| Capability | Implemented? | Where |
|---|---|---|
| Ed25519 identity keypair | ✅ | `identity.IdentityKeyPair.generate` |
| X25519 identity keypair | ✅ | `IdentityKeyPair.generate` (returned alongside Ed25519) |
| Deterministic identity from a 32-byte seed | ✅ | `IdentityKeyPair.fromSeed` (derives both Ed25519 and X25519 via HKDF) |
| Ed25519 sign / verify | ✅ | `IdentityKeyPair.sign`, `verify` |
| X25519 key agreement | ✅ | `crypto.CryptoProvider.x25519Agreement` |
| X3DH handshake (initiator + responder) | ✅ | `protocol.X3DHHandshake.initiate`, `respond` |
| Double Ratchet with skipped-message key store | ✅ | `protocol.DoubleRatchet.encrypt`, `decrypt` |
| Double Ratchet state serialisation | ✅ | `DoubleRatchet.serialize`, `DoubleRatchet.deserialize` |
| Group messaging with sender keys + epochs | ✅ | `group.GroupSession` |
| ChaCha20-Poly1305 AEAD | ✅ | `crypto.CryptoProvider.encrypt/decrypt` |
| HMAC-SHA-256, HKDF, SHA-256, SHA-512 | ✅ | `crypto.CryptoProvider` |
| SecureRandom | ✅ | `crypto.CryptoProvider.secureRandom` |
| HTTP transport (REST) | ✅ | `transport.HttpTransport` |
| TLS certificate pinning | ✅ | `HttpTransport(url, pinnedCertPem)` — strict mode, no fallback to system CAs |
| Rate-limit / auth / network exception types | ✅ | `exceptions.*` |
| Constant-time byte comparison, secure clear, hex utils | ✅ | `Utils` |

What is **not** implemented:

- ❌ Safety number / verification QR — not present.
- ❌ WebSocket transport — not present. The Java SDK communicates with the relay over HTTP only.
- ❌ Padding helpers — the Java SDK does not include block-aligned padding; the application is responsible for padding ciphertext before it is sent over the relay.

## Requirements

- Java 17+ (uses `getInstance("X25519")` from the JDK 11+ crypto provider and `EdDSA` from JDK 15+).
- Maven 3.6+.

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.sibna</groupId>
    <artifactId>sibna-protocol</artifactId>
    <version>3.0.1</version>
</dependency>
```

The package is not currently published to Maven Central. Build it from this source tree:

```bash
cd sdks/java
mvn install
```

## Module layout

```
sdks/java/
├── src/main/java/com/sibna/
│   ├── SibnaClient.java         # Top-level client (sessions, groups, transport)
│   ├── Utils.java               # hex, constant-time compare, secure clear
│   ├── crypto/
│   │   └── CryptoProvider.java  # ChaCha20-Poly1305, HKDF, SHA, HMAC, X25519, Ed25519
│   ├── identity/
│   │   ├── IdentityKeyPair.java # Ed25519 + X25519 keypair
│   │   └── PreKeyBundle.java    # For X3DH
│   ├── protocol/
│   │   ├── X3DHHandshake.java   # initiate() / respond()
│   │   └── DoubleRatchet.java   # forward + future secrecy
│   ├── group/
│   │   └── GroupSession.java    # Sender keys, epochs
│   ├── transport/
│   │   └── HttpTransport.java   # REST + TLS pinning
│   └── exceptions/
│       ├── SibnaException.java
│       ├── AuthException.java
│       ├── CryptoException.java
│       ├── InvalidArgumentException.java
│       ├── NetworkException.java
│       ├── RateLimitException.java
│       └── SessionException.java
├── src/test/java/com/sibna/
│   ├── IdentityTest.java
│   └── SessionTest.java
├── pom.xml
└── README.md
```

## Quick start

```java
import com.sibna.SibnaClient;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.identity.PreKeyBundle;
import com.sibna.protocol.DoubleRatchet;
import com.sibna.group.GroupSession;
import com.sibna.exceptions.SibnaException;

public class Example {
    public static void main(String[] args) throws SibnaException {
        // 1. Create a client. Optional TLS pinning via PEM string.
        SibnaClient client = new SibnaClient("https://sibna.example.com");
        // To pin: new SibnaClient(url, "-----BEGIN CERTIFICATE-----\n…");

        // 2. Generate or load an identity.
        IdentityKeyPair identity = client.generateIdentity();
        // Or: client.loadIdentity(seed32bytes);

        // 3. Authenticate (challenge-response → JWT).
        String token = client.authenticate();
        // (not stored on the client — pass it back to sendMessage if needed)

        // 4. Open a session with a peer via X3DH.
        PreKeyBundle peerBundle = fetchPeerPreKeyBundle(); // implemented by your app
        DoubleRatchet session = client.createSession("peer-hex-id", peerBundle);

        // 5. Encrypt and send.
        byte[] ciphertext = session.encrypt("hello world".getBytes());
        client.sendMessage("peer-hex-id", ciphertext);

        // 6. Receive and decrypt.
        byte[] incoming = receiveSealedMessage(); // implemented by your app
        byte[] plaintext = session.decrypt(incoming);
    }
}
```

## API reference

### `class SibnaClient`

```java
public class SibnaClient implements AutoCloseable
```

| Method | Description |
|---|---|
| `SibnaClient(String serverUrl)` | Construct with the relay URL. |
| `SibnaClient(String serverUrl, String pinnedCertPem)` | Same, with TLS pinning. The PEM is the only trust anchor. |
| `generateIdentity() → IdentityKeyPair` | Random Ed25519+X25519 keypair. |
| `loadIdentity(byte[] seed) → IdentityKeyPair` | Derive both keys from a 32-byte seed via HKDF. |
| `getIdentity() → Optional<IdentityKeyPair>` | Currently loaded identity, if any. |
| `authenticate() → String` | Ed25519 challenge-response → JWT. Throws `AuthException` on 401, `NetworkException` on transport failure. |
| `createSession(String peerId, PreKeyBundle peerBundle) → DoubleRatchet` | Performs X3DH `initiate`, then returns a `DoubleRatchet` initialised as the initiator. The session is stored in the client and can be retrieved with `getSession`. |
| `acceptSession(String peerId, byte[] ephemeralPublicKey, byte[] identityPublicKey, byte[] prekey) → DoubleRatchet` | Performs X3DH `respond` (for the receiver of an initial message). |
| `encryptMessage(String peerId, byte[] plaintext) → byte[]` | Routes through the stored `DoubleRatchet` for that peer. Throws `SessionException` if no session exists. |
| `decryptMessage(String peerId, byte[] ciphertext) → byte[]` | Routes through the stored `DoubleRatchet` for that peer. |
| `sendMessage(String recipientId, byte[] ciphertext)` | `POST /v1/messages/send` (requires a JWT in the client — currently the `authenticate()` JWT is **not** persisted on the client; you may need to extend the client or call `HttpTransport.sendMessage` directly with the token). |
| `createGroup(byte[] groupId) → GroupSession` | Create a sender-key group. |
| `getGroup(byte[] groupId) → Optional<GroupSession>` | Retrieve an existing group. |
| `getSession(String peerId) → Optional<DoubleRatchet>` | Retrieve an existing session. |
| `isAuthenticated() → boolean` | True if a JWT was obtained. |
| `hasSession(String peerId) → boolean` | True if a session exists for that peer. |
| `getSessionCount() → int` | Number of active sessions. |
| `getGroupCount() → int` | Number of active groups. |
| `removeSession(String peerId)` | Drop the session and zero its keys. |
| `leaveGroup(byte[] groupId)` | Drop the group and zero its keys. |
| `close()` | Close all sessions and groups, zero all keys, drop the identity. |

### `class IdentityKeyPair`

```java
public static IdentityKeyPair generate(CryptoProvider crypto)
public static IdentityKeyPair fromSeed(CryptoProvider crypto, byte[] seed)
```

`fromSeed` uses HKDF-SHA-256 with two distinct info strings (`"sibna_ed25519_v3"` and `"sibna_x25519_v3"`) to derive both keys. Both intermediate seeds are zeroed after the key factories are invoked.

| Method | Description |
|---|---|
| `getEd25519PublicKey() / getEd25519PrivateKey()` | Ed25519 `java.security.Key` objects. |
| `getX25519PublicKey() / getX25519PrivateKey()` | X25519 `java.security.Key` objects. |
| `getPublicKeyHex() → String` | 64-character hex of the Ed25519 public key. |
| `sign(byte[] data) → byte[]` | 64-byte Ed25519 signature. |
| `verify(byte[] data, byte[] signature) → boolean` | Constant-time-ish via the JDK provider. |
| `x25519Agreement(PublicKey peerPublicKey) → byte[]` | 32-byte X25519 shared secret. |
| `clear()` | Best-effort zero of the encoded forms of the private keys. |

### `class PreKeyBundle`

Used for X3DH. Contains an Ed25519 identity key, an X25519 signed prekey, an Ed25519 signature over the prekey, and an optional one-time prekey.

| Method | Description |
|---|---|
| `PreKeyBundle.create(crypto, identity, signedPrekeyPublic, signature, onetimePrekeyPublic)` | Construct. The bundle expires after 7 days. |
| `toBytes() → byte[]` | Wire format: `identity(32) ‖ spk(32) ‖ sig(64) ‖ has_otp(1) ‖ otp?(32)`. |
| `getIdentityKey() / getSignedPrekey() / getSignature() / getOnetimePrekey()` | Defensive copies. |
| `hasOnetimePrekey() → boolean` |  |
| `isExpired() → boolean` | True if older than 7 days. |
| `getIdentityKeyHex() → String` | 64-character hex. |

### `class X3DHHandshake`

Implements the standard X3DH key agreement with 3 or 4 DH operations:

| Method | Description |
|---|---|
| `initiate(PreKeyBundle peerBundle) → byte[]` | Alice. DH1 = IK_A · SPK_B, DH2 = EK_A · IK_B, DH3 = EK_A · SPK_B, optional DH4 = EK_A · OPK_B. Result is HKDF-SHA-256 of the concatenation with info `"SibnaProtocol_X3DH"`. |
| `respond(byte[] ephemeralPublicKey, byte[] identityPublicKey, byte[] prekey) → byte[]` | Bob. DH1 = SPK_B · IK_A, DH2 = IK_B · EK_A, DH3 = SPK_B · EK_A. Same HKDF extraction. |

The DH intermediate values are zeroed before the method returns.

### `class DoubleRatchet`

Symmetric-state ratchet. Implements both the KDF-chain ratchet (per-message keys) and the DH ratchet (per-message forward secrecy step).

| Method | Description |
|---|---|
| `DoubleRatchet(crypto, sharedSecret, isInitiator)` | Initialise from the X3DH shared secret. |
| `encrypt(byte[] plaintext) → byte[]` | KDF-chain step → ChaCha20-Poly1305 → return `header ‖ ciphertext`. |
| `decrypt(byte[] message) → byte[]` | Parse header → DH ratchet if needed → KDF-chain step → decrypt. Skipped message keys are buffered (up to 2000 entries) for out-of-order delivery. |
| `serialize() → byte[]` | 176-byte state: `version(4) ‖ root(32) ‖ send_chain(32) ‖ send_idx(4) ‖ recv_chain(32) ‖ recv_idx(4) ‖ remote_dh(32) ‖ prev_counter(4)`. |
| `DoubleRatchet.deserialize(crypto, data)` | Restore state. |
| `getStats() → Stats` | `{messagesSent, messagesReceived}`. |
| `close()` | Zero root chain, sending chain, receiving chain, and remote DH key. |

Throws `CryptoException` on:
- empty plaintext,
- a header that fails to parse,
- AEAD tag mismatch (the underlying `ChaCha20-Poly1305` decryption fails).

### `class GroupSession`

Sender-key group messaging. Each member publishes a per-group sender key; the group increments an `epoch` counter on every membership change.

| Method | Description |
|---|---|
| `GroupSession(crypto, groupId, identity)` | New group. Generates a random 32-byte sender key. |
| `addMember(String publicKeyHex, byte[] senderKey)` | Register a member's sender key. |
| `removeMember(String publicKeyHex)` | Drop the member and increment the epoch. |
| `importSenderKey(String publicKeyHex, byte[] senderKey)` | Update a member's sender key without changing membership. |
| `encrypt(byte[] plaintext) → byte[]` | Ratchets `mySenderKey = HKDF(mySenderKey, "SibnaGroup_Ratchet")`, then ChaCha20-Poly1305 with `groupId` as the AAD. |
| `decrypt(String senderPublicKeyHex, byte[] ciphertext) → byte[]` | Looks up the sender's last-known key and decrypts. |
| `getSenderKey() → byte[]` | Defensive copy of the current sender key (for distribution to other members). |
| `getGroupId() → byte[]` | Defensive copy. |
| `getEpoch() → long` | Current epoch counter. |
| `getMemberCount() → int` |  |
| `leave()` | Zero the local sender key, drop all members, increment epoch. |

### `class HttpTransport`

```java
public HttpTransport(String baseUrl)
public HttpTransport(String baseUrl, String pinnedCertPem)
```

| Method | Description |
|---|---|
| `requestChallenge(String identityKeyHex) → byte[]` | `POST /v1/auth/challenge`. |
| `proveOwnership(String identityKeyHex, byte[] challenge, byte[] signature) → String` | `POST /v1/auth/prove`. Returns the JWT. |
| `sendMessage(String recipientId, byte[] ciphertext, String jwtToken)` | `POST /v1/messages/send`. |
| `uploadPrekey(String bundleHex, boolean isLastResort, String jwtToken)` | `POST /v1/prekeys/upload`. |
| `fetchPrekeys(String rootIdHex) → String` | `GET /v1/prekeys/{root_id}`. Returns the raw JSON; parse with your library of choice. |
| `fetchInbox(String identityKeyHex, String jwtToken) → String` | `GET /v1/messages/inbox?…`. |
| `health() → String` | `GET /health`. |

TLS pinning uses an `X509TrustManager` that compares every certificate in the chain to the pinned PEM. Any mismatch raises `SecurityException`. The pinned cert is the only trust anchor — the system CA store is not consulted.

### Exceptions

| Class | HTTP status / cause |
|---|---|
| `SibnaException` | base |
| `AuthException` | 401 |
| `CryptoException` | ChaCha20-Poly1305, X25519, Ed25519, HKDF failures |
| `InvalidArgumentException` | bad arguments (e.g. seed not 32 bytes) |
| `NetworkException` | HTTP transport failures |
| `RateLimitException` | 429 |
| `SessionException` | session not found for that peer |

## Security notes

- All key material is zeroed when `close()` is called, when a session is removed, or when a group is left. The clear is best-effort — some `java.security.Key` implementations do not expose their raw bytes.
- The KDF ratchet uses `HKDF-SHA-256(salt=null, info={0x01} or {0x02})` for the per-message step and `HKDF-SHA-256(salt=null, info="SibnaProtocol_RootChain")` for the root chain step.
- Constant-time comparison is provided by `Utils.constantTimeEquals`. The cryptographic primitives themselves (Ed25519 verify, ChaCha20-Poly1305 AEAD) are implemented inside the JDK and inherit the platform's side-channel resistance.
- The HTTP transport has a 30-second connect and read timeout.
- The TLS pinning check fails closed: a mismatched certificate raises `SecurityException`, which is propagated as a connection failure.

## Limitations

- The Java SDK does not implement safety numbers or QR-code verification. To verify a peer's identity out of band, exchange fingerprints manually.
- There is no WebSocket transport — the Java SDK talks to the relay over HTTP only.
- The Java SDK does not provide block-aligned padding for the application message. If you need metadata-resistant padding, pad the ciphertext yourself or pair this SDK with a relay that pads.
- `SibnaClient.authenticate()` returns the JWT but does not currently store it for reuse. To send a message with the same token, pass the token to `HttpTransport.sendMessage` directly.
- The package is not currently published to Maven Central. Build from source.

## License

Apache-2.0 OR MIT
