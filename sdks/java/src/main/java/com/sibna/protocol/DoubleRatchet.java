package com.sibna.protocol;

import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Double Ratchet Algorithm (Sibna Protocol v3.0.1) — matches Rust core exactly.
 *
 * Critical invariants (from Rust core/ratchet/session.rs):
 *  - Initial KDF: HKDF(salt="SibnaSession_v3", ikm=shared_secret)
 *                   .expand("SibnaRootAndChainKey_v3", 64) → root(32) + chain(32)
 *  - Only ONE initial chain: initiator→sending, responder→receiving
 *  - KDF_RK: HKDF(salt=root_key, ikm=dh_out, info="SibnaRatchet_v3", L=64)
 *  - Chain: mk=HMAC(ck,0x01), next_ck=HMAC(ck,0x02)
 *  - msg_num = SENDING CHAIN INDEX BEFORE advance (NOT global counter)
 *  - Wire: dh_public(32) || msg_num(4 LE) || nonce(12) || encrypted
 *  - Nonce: random(8) || msg_num_le(4)
 *  - Header: dh_public(32) || msg_num(8 LE) || prev_chain_len(8 LE) || timestamp(8 LE) = 56 bytes
 *  - Encryptor: initial_message_number=0, counter tracks own sequence
 */
public class DoubleRatchet implements AutoCloseable {
    private final CryptoProvider crypto;

    public static final int MAX_SKIPPED_MESSAGES = 2000;
    public static final int MAX_CHAIN_MESSAGES = 4000;
    public static final int MIN_COMPATIBLE_VERSION = 9;

    // Root key for DH ratchet
    private byte[] rootKey;

    // Local DH key pair (X25519)
    private KeyPair dhLocalKeyPair;
    // Raw 32-byte local public key bytes (for header construction)
    private byte[] dhLocalPubBytes;

    // Remote DH public key (X25519, 32 bytes)
    private byte[] dhRemotePub;

    // Sending chain
    private byte[] sendingChainKey;
    private int sendingChainIndex; // = msg_num BEFORE advance

    // Receiving chain
    private byte[] receivingChainKey;
    private int receivingChainIndex;

    // Previous sending chain length for the header (set during DH ratchet)
    private int previousCounter;

    // Skipped message keys: key = "dhpub_hex:msg_num", value = message_key
    private final Map<String, byte[]> skippedMessageKeys;
    private final Map<String, byte[]> skippedDhPubKeys;

    private volatile boolean closed = false;

    /**
     * Initialize from a shared secret (post-X3DH).
     *
     * @param crypto       crypto provider
     * @param sharedSecret 32-byte shared secret from X3DH
     * @param isInitiator  true if we initiated the session
     */
    public DoubleRatchet(CryptoProvider crypto, byte[] sharedSecret, boolean isInitiator)
            throws CryptoException {
        this.crypto = crypto;
        this.skippedMessageKeys = new LinkedHashMap<String, byte[]>(MAX_SKIPPED_MESSAGES, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, byte[]> eldest) {
                return size() > MAX_SKIPPED_MESSAGES;
            }
        };
        this.skippedDhPubKeys = new ConcurrentHashMap<>();
        this.previousCounter = 0;

        // Initial KDF: HKDF(salt="SibnaSession_v3", ikm=shared_secret)
        //               .expand("SibnaRootAndChainKey_v3", 64) → root(32) + chain(32)
        byte[] kdfResult = crypto.hkdf(
                "SibnaSession_v3".getBytes(),
                sharedSecret,
                "SibnaRootAndChainKey_v3".getBytes(),
                64
        );
        this.rootKey = Arrays.copyOfRange(kdfResult, 0, 32);
        byte[] chainKey = Arrays.copyOfRange(kdfResult, 32, 64);
        Arrays.fill(kdfResult, (byte) 0);

        if (isInitiator) {
            this.sendingChainKey = chainKey;
            this.receivingChainKey = null;
        } else {
            this.sendingChainKey = null;
            this.receivingChainKey = chainKey;
        }
        this.sendingChainIndex = 0;
        this.receivingChainIndex = 0;

        // Generate initial local DH key pair
        this.dhLocalKeyPair = crypto.generateX25519KeyPair();
        this.dhLocalPubBytes = extractRawPublicKey(dhLocalKeyPair.getPublic());
        this.dhRemotePub = null;
    }

    /**
     * Constructor for deserialization / restoration.
     */
    private DoubleRatchet(CryptoProvider crypto) {
        this.crypto = crypto;
        this.skippedMessageKeys = new LinkedHashMap<String, byte[]>(MAX_SKIPPED_MESSAGES, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, byte[]> eldest) {
                return size() > MAX_SKIPPED_MESSAGES;
            }
        };
        this.skippedDhPubKeys = new ConcurrentHashMap<>();
    }

    // ────────────────────── ENCRYPT ──────────────────────

    public byte[] encrypt(byte[] plaintext) throws CryptoException {
        ensureOpen();
        if (plaintext == null) throw new CryptoException("Plaintext cannot be null");

        // If no sending chain, perform send-side DH ratchet
        if (sendingChainKey == null) {
            performSendRatchet();
        }

        // Derive header key from sending chain BEFORE advancing
        byte[] headerKey = deriveKey(sendingChainKey, (byte) 0x03);

        // Check chain exhaustion
        if (sendingChainIndex >= MAX_CHAIN_MESSAGES) {
            throw new CryptoException("Sending chain exhausted");
        }

        // msg_num = SENDING CHAIN INDEX BEFORE advance
        int msgNum = sendingChainIndex;

        // Ratchet: mk=HMAC(ck,0x01), next_ck=HMAC(ck,0x02)
        byte[] messageKey = deriveKey(sendingChainKey, (byte) MESSAGE_KEY_SEED);
        byte[] nextChainKey = deriveKey(sendingChainKey, (byte) CHAIN_KEY_SEED);
        System.arraycopy(nextChainKey, 0, sendingChainKey, 0, 32);
        Arrays.fill(nextChainKey, (byte) 0);
        sendingChainIndex++;

        // Build header: dh_pub(32) || msg_num(8 LE) || prev_chain_len(8 LE) || timestamp(8 LE) = 56 bytes
        byte[] header = buildHeader(msgNum);

        // Encrypt: nonce(12) = random(8) || msg_num_le(4)
        //          wire = header || nonce || ciphertext || tag
        byte[] ciphertext = crypto.encryptWithNonceCounter(messageKey, plaintext, header, msgNum);

        // Combine: header + ciphertext (which includes nonce + ciphertext + tag)
        byte[] result = new byte[header.length + ciphertext.length];
        System.arraycopy(header, 0, result, 0, header.length);
        System.arraycopy(ciphertext, 0, result, header.length, ciphertext.length);

        Arrays.fill(messageKey, (byte) 0);
        return result;
    }

    // ────────────────────── DECRYPT ──────────────────────

    public byte[] decrypt(byte[] message) throws CryptoException {
        ensureOpen();
        if (message == null || message.length < 56 + 12 + 16) {
            throw new CryptoException("Message too short");
        }

        // Parse header: dh_pub(32) || msg_num(8 LE) || prev_chain_len(8 LE) || timestamp(8 LE)
        byte[] remoteDhPub = Arrays.copyOfRange(message, 0, 32);
        int msgNum = (int) bytesToLongLE(message, 32);
        int prevChainLen = (int) bytesToLongLE(message, 40);
        long originalTimestamp = bytesToLongLE(message, 48);

        if (msgNum < 0 || msgNum > MAX_CHAIN_MESSAGES) {
            throw new CryptoException("Invalid message number");
        }

        // Validate the remote DH public key (low-order point rejection)
        if (!crypto.validatePublicKey(remoteDhPub)) {
            throw new CryptoException("Invalid DH public key (low-order point)");
        }

        // Check if this is a DH ratchet step (new remote key)
        boolean needsRatchet = (dhRemotePub == null)
                || !Arrays.equals(remoteDhPub, dhRemotePub);

        // Try skipped message keys first
        String skipKey = bytesToHex(remoteDhPub) + ":" + msgNum;
        byte[] skippedMk = skippedMessageKeys.remove(skipKey);
        if (skippedMk != null) {
            // Reconstruct header for AD using original timestamp
            byte[] header = buildHeaderForDecrypt(remoteDhPub, msgNum, prevChainLen, originalTimestamp);
            byte[] encryptedPart = Arrays.copyOfRange(message, 56, message.length);
            try {
                return crypto.decryptWithNonceCounter(skippedMk, encryptedPart, header);
            } finally {
                Arrays.fill(skippedMk, (byte) 0);
                skippedDhPubKeys.remove(skipKey);
            }
        }

        if (needsRatchet) {
            // Save previous sending chain length for header
            previousCounter = (sendingChainKey != null) ? sendingChainIndex : 0;

            // Skip message keys on receiving chain up to previous chain length
            skipMessageKeysUntil(receivingChainKey, receivingChainIndex, prevChainLen);

            // Perform full DH ratchet
            dhRatchetStep(remoteDhPub);
        }

        // Skip message keys up to msg_num on receiving chain
        skipMessageKeysUntil(receivingChainKey, receivingChainIndex, msgNum);

        // Derive message key at msg_num: ratchet chain key
        if (receivingChainKey == null) {
            throw new CryptoException("No receiving chain after ratchet");
        }
        byte[] messageKey = deriveKey(receivingChainKey, (byte) MESSAGE_KEY_SEED);
        byte[] nextReceivingChain = deriveKey(receivingChainKey, (byte) CHAIN_KEY_SEED);
        System.arraycopy(nextReceivingChain, 0, receivingChainKey, 0, 32);
        Arrays.fill(nextReceivingChain, (byte) 0);
        receivingChainIndex++;

        // Build header for AD verification using original timestamp
        byte[] header = buildHeaderForDecrypt(remoteDhPub, msgNum, prevChainLen, originalTimestamp);
        byte[] encryptedPart = Arrays.copyOfRange(message, 56, message.length);

        try {
            byte[] plaintext = crypto.decryptWithNonceCounter(messageKey, encryptedPart, header);
            Arrays.fill(messageKey, (byte) 0);
            return plaintext;
        } catch (CryptoException e) {
            Arrays.fill(messageKey, (byte) 0);
            throw e;
        }
    }

    // ────────────────────── SEND-SIDE DH RATCHET ──────────────────────

    /**
     * Perform send-side DH ratchet when there's no sending chain.
     * Matches Rust perform_dh_ratchet: generate new local, DH(new_local, remote),
     * KDF_RK → root + sending_chain.
     */
    private void performSendRatchet() throws CryptoException {
        KeyPair newLocal = crypto.generateX25519KeyPair();
        byte[] newLocalPub = extractRawPublicKey(newLocal.getPublic());

        if (dhRemotePub != null) {
            // DH(new_local, remote)
            PrivateKey newLocalPriv = newLocal.getPrivate();
            PublicKey remotePub = bytesToPublicKey(dhRemotePub);
            byte[] dhOutput = crypto.x25519Agreement(newLocalPriv, remotePub);

            // KDF_RK(root_key, dh_output) → new_root(32) + sending_chain(32)
            byte[] kdfResult = kdfRk(rootKey, dhOutput);
            byte[] newRoot = Arrays.copyOfRange(kdfResult, 0, 32);
            byte[] sendChainKey = Arrays.copyOfRange(kdfResult, 32, 64);
            Arrays.fill(kdfResult, (byte) 0);
            Arrays.fill(dhOutput, (byte) 0);

            System.arraycopy(newRoot, 0, rootKey, 0, 32);
            Arrays.fill(newRoot, (byte) 0);

            if (sendingChainKey != null) Arrays.fill(sendingChainKey, (byte) 0);
            sendingChainKey = sendChainKey;
            sendingChainIndex = 0;
        }

        // Update local DH key pair
        if (dhLocalKeyPair != null) {
            // Clear old private key material
            Arrays.fill(dhLocalPubBytes, (byte) 0);
        }
        dhLocalKeyPair = newLocal;
        dhLocalPubBytes = newLocalPub;
    }

    // ────────────────────── DH RATCHET STEP ──────────────────────

    /**
     * Full DH ratchet when receiving a new remote key.
     * Matches Rust dh_ratchet exactly:
     *   1. Use EXISTING local key → receive step → receiving chain
     *   2. Generate NEW local key → send step → sending chain
     */
    private void dhRatchetStep(byte[] newRemoteDhPub) throws CryptoException {
        // ── Receive step: use EXISTING local key ──
        if (dhLocalKeyPair != null) {
            PrivateKey localPriv = dhLocalKeyPair.getPrivate();
            PublicKey remotePub = bytesToPublicKey(newRemoteDhPub);
            byte[] dhOutput = crypto.x25519Agreement(localPriv, remotePub);

            byte[] kdfResult = kdfRk(rootKey, dhOutput);
            byte[] newRoot = Arrays.copyOfRange(kdfResult, 0, 32);
            byte[] recvChainKey = Arrays.copyOfRange(kdfResult, 32, 64);
            Arrays.fill(kdfResult, (byte) 0);
            Arrays.fill(dhOutput, (byte) 0);

            System.arraycopy(newRoot, 0, rootKey, 0, 32);
            Arrays.fill(newRoot, (byte) 0);

            if (receivingChainKey != null) Arrays.fill(receivingChainKey, (byte) 0);
            receivingChainKey = recvChainKey;
            receivingChainIndex = 0;
        }

        // Update remote key
        dhRemotePub = Arrays.copyOf(newRemoteDhPub, 32);

        // ── Send step: generate NEW local key ──
        KeyPair newLocal = crypto.generateX25519KeyPair();
        byte[] newLocalPub = extractRawPublicKey(newLocal.getPublic());
        PrivateKey newLocalPriv = newLocal.getPrivate();
        PublicKey remotePub = bytesToPublicKey(newRemoteDhPub);
        byte[] dhOutput2 = crypto.x25519Agreement(newLocalPriv, remotePub);

        byte[] kdfResult2 = kdfRk(rootKey, dhOutput2);
        byte[] newRoot2 = Arrays.copyOfRange(kdfResult2, 0, 32);
        byte[] sendChainKey = Arrays.copyOfRange(kdfResult2, 32, 64);
        Arrays.fill(kdfResult2, (byte) 0);
        Arrays.fill(dhOutput2, (byte) 0);

        System.arraycopy(newRoot2, 0, rootKey, 0, 32);
        Arrays.fill(newRoot2, (byte) 0);

        if (sendingChainKey != null) Arrays.fill(sendingChainKey, (byte) 0);
        sendingChainKey = sendChainKey;
        sendingChainIndex = 0;

        // Update local DH key pair
        if (dhLocalKeyPair != null) Arrays.fill(dhLocalPubBytes, (byte) 0);
        dhLocalKeyPair = newLocal;
        dhLocalPubBytes = newLocalPub;
    }

    // ────────────────────── KEY DERIVATION ──────────────────────

    /**
     * Chain key ratchet: HMAC-SHA256(ck, seed) where seed is 0x01 (mk) or 0x02 (next_ck).
     * Matches Rust chain.rs derive_key.
     */
    private byte[] deriveKey(byte[] chainKey, byte seed) throws CryptoException {
        return crypto.hmacSha256(chainKey, new byte[]{seed});
    }

    private static final byte MESSAGE_KEY_SEED = 0x01;
    private static final byte CHAIN_KEY_SEED = 0x02;

    /**
     * KDF_RK: HKDF(salt=root_key, ikm=dh_out, info="SibnaRatchet_v3", L=64)
     * Returns root_key(32) || chain_key(32).
     * Matches Rust kdf.rs RatchetKdf::kdf_rk (symmetric mode).
     */
    private byte[] kdfRk(byte[] rootKey, byte[] dhOutput) throws CryptoException {
        return crypto.hkdf(rootKey, dhOutput, "SibnaRatchet_v3".getBytes(), 64);
    }

    /**
     * Skip message keys on receiving chain up to target index.
     * Stores skipped message keys for later out-of-order decryption.
     */
    private void skipMessageKeysUntil(byte[] chainKey, int currentIdx, int targetIdx)
            throws CryptoException {
        if (chainKey == null) return;
        if (targetIdx <= currentIdx) return;
        if (targetIdx - currentIdx > MAX_SKIPPED_MESSAGES) {
            throw new CryptoException("Too many skipped messages: " + (targetIdx - currentIdx));
        }

        byte[] chain = Arrays.copyOf(chainKey, 32);
        int idx = currentIdx;
        while (idx < targetIdx) {
            byte[] mk = deriveKey(chain, (byte) MESSAGE_KEY_SEED);
            byte[] nextCk = deriveKey(chain, (byte) CHAIN_KEY_SEED);
            System.arraycopy(nextCk, 0, chain, 0, 32);
            Arrays.fill(nextCk, (byte) 0);

            // Store skipped key (if not the last one — the last one is consumed by the caller)
            if (idx + 1 < targetIdx) {
                String key = bytesToHex(dhRemotePub != null ? dhRemotePub : new byte[32])
                        + ":" + idx;
                if (skippedMessageKeys.size() < MAX_SKIPPED_MESSAGES) {
                    skippedMessageKeys.put(key, mk);
                    skippedDhPubKeys.put(key, dhRemotePub != null
                            ? Arrays.copyOf(dhRemotePub, 32) : new byte[32]);
                }
            }
            idx++;
        }
        // Copy advanced chain key back
        System.arraycopy(chain, 0, chainKey, 0, 32);
        Arrays.fill(chain, (byte) 0);
    }

    // ────────────────────── HEADER ──────────────────────

    /**
     * Build header for outgoing messages.
     * Format: dh_public(32) || msg_num(8 LE) || prev_chain_len(8 LE) || timestamp(8 LE) = 56 bytes.
     */
    private byte[] buildHeader(int msgNum) {
        byte[] header = new byte[56];
        System.arraycopy(dhLocalPubBytes, 0, header, 0, 32);
        putLongLE(header, 32, msgNum);
        putLongLE(header, 40, previousCounter);
        putLongLE(header, 48, System.currentTimeMillis() / 1000);
        return header;
    }

    /**
     * Build header for AD verification during decryption.
     * Uses the original timestamp from the incoming message.
     */
    private byte[] buildHeaderForDecrypt(byte[] remoteDhPub, int msgNum, int prevChainLen,
                                          long timestamp) {
        byte[] header = new byte[56];
        System.arraycopy(remoteDhPub, 0, header, 0, 32);
        putLongLE(header, 32, msgNum);
        putLongLE(header, 40, prevChainLen);
        putLongLE(header, 48, timestamp);
        return header;
    }

    // ────────────────────── KEY EXTRACTION ──────────────────────

    /**
     * Extract raw 32-byte public key from X509EncodedKeySpec.
     * BouncyCastle X25519 keys store the raw 32-byte key at the end of the encoding.
     */
    private byte[] extractRawPublicKey(PublicKey publicKey) throws CryptoException {
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null) throw new CryptoException("Cannot extract public key bytes");
        if (encoded.length == 32) return encoded;
        // X.509 SubjectPublicKeyInfo for X25519: 12-byte prefix + 32-byte key
        if (encoded.length == 44) {
            return Arrays.copyOfRange(encoded, 12, 44);
        }
        // Fallback: take last 32 bytes
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private PublicKey bytesToPublicKey(byte[] keyBytes) throws CryptoException {
        try {
            // Wrap raw 32-byte key in X.509 SubjectPublicKeyInfo for X25519
            byte[] x509Prefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
                                  0x6e, 0x03, 0x21, 0x00};
            byte[] x509 = new byte[x509Prefix.length + 32];
            System.arraycopy(x509Prefix, 0, x509, 0, x509Prefix.length);
            System.arraycopy(keyBytes, 0, x509, x509Prefix.length, 32);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("X25519", "BC");
            return kf.generatePublic(new java.security.spec.X509EncodedKeySpec(x509));
        } catch (Exception e) {
            throw new CryptoException("Failed to decode X25519 public key", e);
        }
    }

    // ────────────────────── UTILITIES ──────────────────────

    private static void putLongLE(byte[] buf, int offset, long val) {
        buf[offset]     = (byte) val;
        buf[offset + 1] = (byte) (val >>> 8);
        buf[offset + 2] = (byte) (val >>> 16);
        buf[offset + 3] = (byte) (val >>> 24);
        buf[offset + 4] = (byte) (val >>> 32);
        buf[offset + 5] = (byte) (val >>> 40);
        buf[offset + 6] = (byte) (val >>> 48);
        buf[offset + 7] = (byte) (val >>> 56);
    }

    private static long bytesToLongLE(byte[] data, int offset) {
        return (long)(data[offset]     & 0xFF)
             | ((long)(data[offset + 1] & 0xFF) << 8)
             | ((long)(data[offset + 2] & 0xFF) << 16)
             | ((long)(data[offset + 3] & 0xFF) << 24)
             | ((long)(data[offset + 4] & 0xFF) << 32)
             | ((long)(data[offset + 5] & 0xFF) << 40)
             | ((long)(data[offset + 6] & 0xFF) << 48)
             | ((long)(data[offset + 7] & 0xFF) << 56);
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ────────────────────── STATS / CLOSE ──────────────────────

    public static class Stats {
        public final int sendingIndex;
        public final int receivingIndex;
        public final int skippedKeysCount;

        public Stats(int sendingIndex, int receivingIndex, int skippedKeysCount) {
            this.sendingIndex = sendingIndex;
            this.receivingIndex = receivingIndex;
            this.skippedKeysCount = skippedKeysCount;
        }
    }

    public Stats getStats() {
        return new Stats(sendingChainIndex, receivingChainIndex, skippedMessageKeys.size());
    }

    private void ensureOpen() throws CryptoException {
        if (closed) throw new CryptoException("DoubleRatchet is closed");
    }

    @Override
    public void close() {
        closed = true;
        if (rootKey != null) Arrays.fill(rootKey, (byte) 0);
        if (sendingChainKey != null) Arrays.fill(sendingChainKey, (byte) 0);
        if (receivingChainKey != null) Arrays.fill(receivingChainKey, (byte) 0);
        if (dhLocalPubBytes != null) Arrays.fill(dhLocalPubBytes, (byte) 0);
        if (dhRemotePub != null) Arrays.fill(dhRemotePub, (byte) 0);
        skippedMessageKeys.clear();
        skippedDhPubKeys.clear();
    }
}
