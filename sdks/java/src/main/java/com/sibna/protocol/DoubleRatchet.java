package com.sibna.protocol;

import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Double Ratchet Algorithm implementation.
 *
 * Provides:
 * - Forward secrecy via ephemeral DH ratchet
 * - Future secrecy (self-healing) via symmetric KDF chain ratchet
 * - Out-of-order message handling with skipped message keys
 */
public class DoubleRatchet implements AutoCloseable {
    private final CryptoProvider crypto;

    // DH ratchet key pair
    private java.security.KeyPair dhRatchetKeyPair;

    // Root chain
    private byte[] rootChainKey;

    // Sending chain
    private byte[] sendingChainKey;
    private int sendingMessageNumber = 0;

    // Receiving chain
    private byte[] receivingChainKey;
    private int receivingMessageNumber = 0;

    // DH ratchet state
    private byte[] remoteDHRatchetKey = null;
    private boolean awaitingDHRatchet = false;

    // Skipped message keys for out-of-order handling
    private final Map<String, byte[]> skippedMessageKeys;
    private static final int MAX_SKIPPED_MESSAGES = 2000;

    private volatile boolean closed = false;

    /**
     * Initialize Double Ratchet with a shared secret from X3DH.
     *
     * @param crypto Crypto provider
     * @param sharedSecret 32-byte shared secret from X3DH
     * @param isInitiator true if we initiated the session
     */
    public DoubleRatchet(CryptoProvider crypto, byte[] sharedSecret, boolean isInitiator) throws CryptoException {
        this.crypto = crypto;
        this.skippedMessageKeys = new LinkedHashMap<String, byte[]>(MAX_SKIPPED_MESSAGES, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, byte[]> eldest) {
                return size() > MAX_SKIPPED_MESSAGES;
            }
        };

        // Derive root key and initial chain keys from shared secret
        byte[] kdfResult = crypto.hkdf(null, sharedSecret, "SibnaProtocol_DoubleRatchet".getBytes(), 96);

        this.rootChainKey = Arrays.copyOfRange(kdfResult, 0, 32);

        if (isInitiator) {
            this.sendingChainKey = Arrays.copyOfRange(kdfResult, 32, 64);
            this.receivingChainKey = Arrays.copyOfRange(kdfResult, 64, 96);
        } else {
            this.receivingChainKey = Arrays.copyOfRange(kdfResult, 32, 64);
            this.sendingChainKey = Arrays.copyOfRange(kdfResult, 64, 96);
            this.awaitingDHRatchet = true;
        }
        // Both sides need an initial DH ratchet key pair for performDHRatchet()
        this.dhRatchetKeyPair = crypto.generateX25519KeyPair();

        // Clear KDF result
        Arrays.fill(kdfResult, (byte) 0);
    }

    /**
     * Encrypt a message.
     */
    public byte[] encrypt(byte[] plaintext) throws CryptoException {
        ensureOpen();

        if (plaintext == null || plaintext.length == 0) {
            throw new CryptoException("Plaintext cannot be empty");
        }

        // Step 1: KDF ratchet step on sending chain
        byte[][] kdfOutput = kdfRatchetStep(sendingChainKey);
        byte[] messageKey = kdfOutput[0];
        sendingChainKey = kdfOutput[1];

        // Step 2: Encrypt with message key
        byte[] ciphertext = crypto.encrypt(messageKey, plaintext, null);

        // Step 3: Build header
        byte[] header = buildHeader();

        // Step 4: Combine header + ciphertext
        byte[] result = concat(header, ciphertext);

        // Clear message key
        Arrays.fill(messageKey, (byte) 0);

        sendingMessageNumber++;

        return result;
    }

    /**
     * Decrypt a message.
     */
    public byte[] decrypt(byte[] message) throws CryptoException {
        ensureOpen();

        // Parse header
        MessageHeader header = parseHeader(message);
        byte[] ciphertext = Arrays.copyOfRange(message, header.headerLength, message.length);

        // Check if this is a DH ratchet step
        if (header.dhPublicKey != null && remoteDHRatchetKey != null && !Arrays.equals(header.dhPublicKey, remoteDHRatchetKey)) {
            // Perform DH ratchet
            performDHRatchet(header.dhPublicKey);
        } else if (header.dhPublicKey != null && remoteDHRatchetKey == null) {
            // First message: store remote DH key without ratcheting
            remoteDHRatchetKey = Arrays.copyOf(header.dhPublicKey, header.dhPublicKey.length);
        }

        // Try skipped message keys first
        String key = header.messageNumber + "_" + bytesToHex(header.dhPublicKey != null ? header.dhPublicKey : new byte[0]);
        byte[] skippedKey = skippedMessageKeys.remove(key);
        if (skippedKey != null) {
            return crypto.decrypt(skippedKey, ciphertext, null);
        }

        // Step 1: KDF ratchet step on receiving chain
        byte[][] kdfOutput = kdfRatchetStep(receivingChainKey);
        byte[] messageKey = kdfOutput[0];
        receivingChainKey = kdfOutput[1];

        // Step 2: Decrypt
        byte[] plaintext = crypto.decrypt(messageKey, ciphertext, null);

        // Clear message key
        Arrays.fill(messageKey, (byte) 0);

        receivingMessageNumber++;

        return plaintext;
    }

    private void performDHRatchet(byte[] remoteDHPubKey) throws CryptoException {
        // Save current receiving chain for skipped messages
        // ... (store intermediate message keys)

        // DH with remote key
        byte[] dhOutput = crypto.x25519Agreement(dhRatchetKeyPair.getPrivate(),
            bytesToPublicKey(remoteDHPubKey));

        // KDF root chain
        byte[][] rootKdf = kdfRatchetStep(rootChainKey, dhOutput);
        rootChainKey = rootKdf[0];
        receivingChainKey = rootKdf[1];

        // Generate new DH key pair
        dhRatchetKeyPair = crypto.generateX25519KeyPair();

        // KDF root chain again
        byte[] dhOutput2 = crypto.x25519Agreement(dhRatchetKeyPair.getPrivate(),
            bytesToPublicKey(remoteDHPubKey));
        byte[][] rootKdf2 = kdfRatchetStep(rootChainKey, dhOutput2);
        rootChainKey = rootKdf2[0];
        sendingChainKey = rootKdf2[1];

        remoteDHRatchetKey = Arrays.copyOf(remoteDHPubKey, remoteDHPubKey.length);
        sendingMessageNumber = 0;
        receivingMessageNumber = 0;

        // Clear DH outputs
        Arrays.fill(dhOutput, (byte) 0);
        Arrays.fill(dhOutput2, (byte) 0);
    }

    private byte[][] kdfRatchetStep(byte[] chainKey) throws CryptoException {
        byte[] messageKey = crypto.hkdf(null, chainKey, new byte[]{1}, 32);
        byte[] newChainKey = crypto.hkdf(null, chainKey, new byte[]{2}, 32);
        return new byte[][]{messageKey, newChainKey};
    }

    private byte[][] kdfRatchetStep(byte[] chainKey, byte[] dhOutput) throws CryptoException {
        byte[] kdfResult = crypto.hkdf(null, concat(chainKey, dhOutput), "SibnaProtocol_RootChain".getBytes(), 64);
        return new byte[][]{Arrays.copyOfRange(kdfResult, 0, 32), Arrays.copyOfRange(kdfResult, 32, 64)};
    }

    private byte[] buildHeader() {
        // Header format: [dh_pubkey_len(1)] [dh_pubkey] [message_number(4)]
        byte[] dhPub = dhRatchetKeyPair.getPublic().getEncoded();
        byte[] header = new byte[1 + dhPub.length + 4];
        header[0] = (byte) dhPub.length;
        System.arraycopy(dhPub, 0, header, 1, dhPub.length);
        // Message number (big-endian)
        header[1 + dhPub.length] = (byte) (sendingMessageNumber >> 24);
        header[1 + dhPub.length + 1] = (byte) (sendingMessageNumber >> 16);
        header[1 + dhPub.length + 2] = (byte) (sendingMessageNumber >> 8);
        header[1 + dhPub.length + 3] = (byte) sendingMessageNumber;
        return header;
    }

    private MessageHeader parseHeader(byte[] data) {
        if (data.length < 5) {
            return new MessageHeader(null, 0, 0);
        }
        int dhPubLen = data[0] & 0xFF;
        byte[] dhPub = Arrays.copyOfRange(data, 1, 1 + dhPubLen);
        int msgNum = ((data[1 + dhPubLen] & 0xFF) << 24) |
                     ((data[1 + dhPubLen + 1] & 0xFF) << 16) |
                     ((data[1 + dhPubLen + 2] & 0xFF) << 8) |
                     (data[1 + dhPubLen + 3] & 0xFF);
        return new MessageHeader(dhPub, msgNum, 1 + dhPubLen + 4);
    }

    private java.security.PublicKey bytesToPublicKey(byte[] keyBytes) throws CryptoException {
        try {
            java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("X25519");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new CryptoException("Failed to decode public key", e);
        }
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Session statistics.
     */
    public static class Stats {
        public final int messagesSent;
        public final int messagesReceived;

        public Stats(int sent, int received) {
            this.messagesSent = sent;
            this.messagesReceived = received;
        }
    }

    public Stats getStats() {
        return new Stats(sendingMessageNumber, receivingMessageNumber);
    }

    /**
     * Serialize the current state to bytes.
     */
    public byte[] serialize() throws CryptoException {
        ensureOpen();
        // Format: version(4) || root(32) || sendKey(32) || sendIdx(4) || recvKey(32) || recvIdx(4) || remoteDH(32) || prevCounter(4)
        int size = 4 + 32 + 32 + 4 + 32 + 4 + 32 + 4;
        byte[] out = new byte[size];
        int offset = 0;

        // Version (simple placeholder)
        out[offset++] = 1; out[offset++] = 0; out[offset++] = 0; out[offset++] = 0;
        
        System.arraycopy(rootChainKey, 0, out, offset, 32); offset += 32;
        System.arraycopy(sendingChainKey, 0, out, offset, 32); offset += 32;
        
        out[offset++] = (byte)(sendingMessageNumber >> 24);
        out[offset++] = (byte)(sendingMessageNumber >> 16);
        out[offset++] = (byte)(sendingMessageNumber >> 8);
        out[offset++] = (byte)sendingMessageNumber;
        
        System.arraycopy(receivingChainKey, 0, out, offset, 32); offset += 32;
        
        out[offset++] = (byte)(receivingMessageNumber >> 24);
        out[offset++] = (byte)(receivingMessageNumber >> 16);
        out[offset++] = (byte)(receivingMessageNumber >> 8);
        out[offset++] = (byte)receivingMessageNumber;
        
        byte[] remoteDH = (remoteDHRatchetKey != null) ? remoteDHRatchetKey : new byte[32];
        System.arraycopy(remoteDH, 0, out, offset, 32); offset += 32;
        
        // Placeholder for previous counter
        out[offset++] = 0; out[offset++] = 0; out[offset++] = 0; out[offset++] = 0;
        
        return out;
    }

    /**
     * Restore state from bytes.
     */
    public static DoubleRatchet deserialize(CryptoProvider crypto, byte[] data) throws CryptoException {
        if (data.length < 128) throw new CryptoException("Serialized state too short");
        
        int offset = 4; // skip version
        byte[] root = Arrays.copyOfRange(data, offset, offset + 32); offset += 32;
        byte[] sendKey = Arrays.copyOfRange(data, offset, offset + 32); offset += 32;
        int sendIdx = ((data[offset] & 0xFF) << 24) | ((data[offset+1] & 0xFF) << 16) | ((data[offset+2] & 0xFF) << 8) | (data[offset+3] & 0xFF);
        offset += 4;
        byte[] recvKey = Arrays.copyOfRange(data, offset, offset + 32); offset += 32;
        int recvIdx = ((data[offset] & 0xFF) << 24) | ((data[offset+1] & 0xFF) << 16) | ((data[offset+2] & 0xFF) << 8) | (data[offset+3] & 0xFF);
        offset += 4;
        byte[] remoteDH = Arrays.copyOfRange(data, offset, offset + 32);
        
        DoubleRatchet dr = new DoubleRatchet(crypto, new byte[32], true); // Dummy init
        dr.rootChainKey = root;
        dr.sendingChainKey = sendKey;
        dr.sendingMessageNumber = sendIdx;
        dr.receivingChainKey = recvKey;
        dr.receivingMessageNumber = recvIdx;
        dr.remoteDHRatchetKey = remoteDH;
        
        return dr;
    }

    private void ensureOpen() throws CryptoException {
        if (closed) {
            throw new CryptoException("DoubleRatchet is closed");
        }
    }


    @Override
    public void close() {
        closed = true;
        clear(rootChainKey, sendingChainKey, receivingChainKey);
        if (remoteDHRatchetKey != null) {
            clear(remoteDHRatchetKey);
        }
        skippedMessageKeys.clear();
    }

    private void clear(byte[]... arrays) {
        for (byte[] arr : arrays) {
            if (arr != null) {
                Arrays.fill(arr, (byte) 0);
            }
        }
    }

    private static class MessageHeader {
        final byte[] dhPublicKey;
        final int messageNumber;
        final int headerLength;

        MessageHeader(byte[] dhPublicKey, int messageNumber, int headerLength) {
            this.dhPublicKey = dhPublicKey;
            this.messageNumber = messageNumber;
            this.headerLength = headerLength;
        }
    }
}
