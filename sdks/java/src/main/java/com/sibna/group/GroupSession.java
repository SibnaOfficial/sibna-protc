package com.sibna.group;

import com.sibna.crypto.CryptoProvider;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.exceptions.CryptoException;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Group messaging session using Sender Keys (Sibna Protocol v3.0.1).
 *
 * Each member maintains a SenderKey chain. Messages are encrypted with the
 * current chain key, deriving a message key and ratcheting the chain forward.
 * SenderKeyMessage carries chain_index for out-of-order decryption.
 */
public class GroupSession {
    private static final int MAX_CHAIN_MESSAGES = 4000;
    private static final int MAX_SKIPPED_MESSAGES = 2000;
    private static final int SENDER_KEY_SIZE = 32;
    private static final int MESSAGE_KEY_SEED = 0x01;
    private static final int CHAIN_KEY_SEED = 0x02;

    private final CryptoProvider crypto;
    private final byte[] groupId;

    // Our own sender key state
    private byte[] myChainKey;
    private int myChainIndex;
    private byte[] mySigningPublicKey;

    // Map from sender identity hex → SenderKeyState
    private final Map<String, SenderKeyState> memberStates;
    private volatile boolean left = false;

    /**
     * Internal state for a single member's sender key chain.
     */
    private static class SenderKeyState {
        final byte[] chainKey;
        int chainIndex;
        // Skipped message keys: map from chain_index → message_key
        final Map<Integer, byte[]> skippedKeys;
        final byte[] signingPublicKey;

        SenderKeyState(byte[] chainKey, byte[] signingPublicKey) {
            this.chainKey = Arrays.copyOf(chainKey, SENDER_KEY_SIZE);
            this.chainIndex = 0;
            this.skippedKeys = new ConcurrentHashMap<>();
            this.signingPublicKey = signingPublicKey != null
                ? Arrays.copyOf(signingPublicKey, signingPublicKey.length)
                : null;
        }
    }

    /**
     * A single encrypted sender key message.
     * Wire format: chain_index(4 LE) || ciphertext
     */
    public static class SenderKeyMessage {
        public final int chainIndex;
        public final byte[] ciphertext;

        public SenderKeyMessage(int chainIndex, byte[] ciphertext) {
            this.chainIndex = chainIndex;
            this.ciphertext = ciphertext;
        }

        public byte[] toBytes() {
            byte[] header = new byte[4];
            header[0] = (byte) chainIndex;
            header[1] = (byte) (chainIndex >>> 8);
            header[2] = (byte) (chainIndex >>> 16);
            header[3] = (byte) (chainIndex >>> 24);
            byte[] out = new byte[4 + ciphertext.length];
            System.arraycopy(header, 0, out, 0, 4);
            System.arraycopy(ciphertext, 0, out, 4, ciphertext.length);
            return out;
        }

        public static SenderKeyMessage fromBytes(byte[] data) throws CryptoException {
            if (data == null || data.length < 4) {
                throw new CryptoException("SenderKeyMessage too short");
            }
            int idx = (data[0] & 0xFF)
                    | ((data[1] & 0xFF) << 8)
                    | ((data[2] & 0xFF) << 16)
                    | ((data[3] & 0xFF) << 24);
            byte[] ct = Arrays.copyOfRange(data, 4, data.length);
            return new SenderKeyMessage(idx, ct);
        }
    }

    /**
     * Create a new group session with an initial sender key chain.
     */
    public GroupSession(CryptoProvider crypto, byte[] groupId, IdentityKeyPair identity)
            throws CryptoException {
        this.crypto = crypto;
        this.groupId = Arrays.copyOf(groupId, groupId.length);
        this.memberStates = new ConcurrentHashMap<>();

        // Generate initial chain key (32 random bytes)
        this.myChainKey = crypto.randomBytes(SENDER_KEY_SIZE);
        this.myChainIndex = 0;

        // Store the signer public key hex for sender identification
        byte[] pkEncoded = identity.getEd25519PublicKey().getEncoded();
        this.mySigningPublicKey = pkEncoded;
    }

    /**
     * Get the current chain key for distribution to group members.
     * After distribution, calling encrypt() will derive message keys from this chain.
     */
    public byte[] getSenderKey() {
        return Arrays.copyOf(myChainKey, SENDER_KEY_SIZE);
    }

    /**
     * Get the current chain index (how many messages have been sent on this chain).
     */
    public int getChainIndex() {
        return myChainIndex;
    }

    /**
     * Import a sender key from another member.
     *
     * @param senderIdentityHex  sender's identity key hex
     * @param chainKey           32-byte chain key
     * @param signingPublicKey   sender's Ed25519 public key bytes (may be null)
     */
    public void importSenderKey(String senderIdentityHex, byte[] chainKey,
                                 byte[] signingPublicKey) {
        if (chainKey == null || chainKey.length != SENDER_KEY_SIZE) return;
        SenderKeyState state = new SenderKeyState(chainKey, signingPublicKey);
        memberStates.put(senderIdentityHex, state);
    }

    /**
     * Remove a member from the group.
     */
    public void removeMember(String senderIdentityHex) {
        SenderKeyState removed = memberStates.remove(senderIdentityHex);
        if (removed != null) {
            Arrays.fill(removed.chainKey, (byte) 0);
            removed.skippedKeys.clear();
        }
    }

    /**
     * Ratchet the sender chain: derive mk = HMAC-SHA256(ck, 0x01), next_ck = HMAC-SHA256(ck, 0x02).
     * Returns the message key and advances the chain.
     */
    private byte[] ratchetChainKey(byte[] chainKey) throws CryptoException {
        byte[] messageKey = crypto.hmacSha256(chainKey, new byte[]{MESSAGE_KEY_SEED});
        byte[] nextChainKey = crypto.hmacSha256(chainKey, new byte[]{CHAIN_KEY_SEED});
        System.arraycopy(nextChainKey, 0, chainKey, 0, SENDER_KEY_SIZE);
        Arrays.fill(nextChainKey, (byte) 0);
        return messageKey;
    }

    /**
     * Derive a message key at a specific index for out-of-order decryption.
     * Advances the chain from its current index to the target, saving skipped keys.
     */
    private byte[] deriveMessageKeyAt(SenderKeyState state, int targetIndex) throws CryptoException {
        while (state.chainIndex < targetIndex) {
            byte[] mk = ratchetChainKey(state.chainKey);
            int idx = state.chainIndex;
            state.chainIndex++;
            if (state.chainIndex < targetIndex && state.skippedKeys.size() < MAX_SKIPPED_MESSAGES) {
                state.skippedKeys.put(idx, mk);
            } else if (state.chainIndex == targetIndex) {
                Arrays.fill(mk, (byte) 0);
                return mk; // not used — caller needs the ratcheted mk
            }
            Arrays.fill(mk, (byte) 0);
        }
        // Now at targetIndex
        byte[] messageKey = ratchetChainKey(state.chainKey);
        state.chainIndex++;
        return messageKey;
    }

    /**
     * Encrypt a group message. Returns a SenderKeyMessage.
     */
    public SenderKeyMessage encrypt(byte[] plaintext) throws CryptoException {
        if (left) throw new CryptoException("Already left the group");
        if (plaintext == null) throw new CryptoException("Plaintext cannot be null");

        byte[] messageKey = ratchetChainKey(myChainKey);
        int currentIndex = myChainIndex;
        myChainIndex++;

        // Encrypt with message key, using groupId as AAD
        byte[] ciphertext = crypto.encryptWithNonceCounter(messageKey, plaintext,
                groupId, currentIndex);
        Arrays.fill(messageKey, (byte) 0);

        return new SenderKeyMessage(currentIndex, ciphertext);
    }

    /**
     * Decrypt a group message from a specific sender.
     *
     * @param senderIdentityHex  sender's identity hex
     * @param message            the SenderKeyMessage to decrypt
     */
    public byte[] decrypt(String senderIdentityHex, SenderKeyMessage message) throws CryptoException {
        if (left) throw new CryptoException("Already left the group");

        SenderKeyState state = memberStates.get(senderIdentityHex);
        if (state == null) {
            throw new CryptoException("No sender key for: " + senderIdentityHex);
        }

        // Check skipped keys first
        byte[] skippedMk = state.skippedKeys.remove(message.chainIndex);
        if (skippedMk != null) {
            try {
                return crypto.decryptWithNonceCounter(skippedMk, message.ciphertext, groupId);
            } finally {
                Arrays.fill(skippedMk, (byte) 0);
            }
        }

        // Derive message key at target index
        if (message.chainIndex < state.chainIndex) {
            throw new CryptoException("Message from already-consumed chain index: " + message.chainIndex);
        }
        if (message.chainIndex - state.chainIndex > MAX_SKIPPED_MESSAGES) {
            throw new CryptoException("Too many skipped messages");
        }

        byte[] mk = deriveMessageKeyAt(state, message.chainIndex);
        try {
            return crypto.decryptWithNonceCounter(mk, message.ciphertext, groupId);
        } finally {
            Arrays.fill(mk, (byte) 0);
        }
    }

    public byte[] getGroupId() { return Arrays.copyOf(groupId, groupId.length); }
    public int getMemberCount() { return memberStates.size(); }

    /**
     * Leave the group and securely clear all keys.
     */
    public void leave() {
        left = true;
        if (myChainKey != null) {
            Arrays.fill(myChainKey, (byte) 0);
            myChainKey = null;
        }
        for (SenderKeyState state : memberStates.values()) {
            Arrays.fill(state.chainKey, (byte) 0);
            state.skippedKeys.clear();
        }
        memberStates.clear();
    }
}
