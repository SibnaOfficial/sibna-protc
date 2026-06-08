package com.sibna;

import com.sibna.crypto.CryptoProvider;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.identity.PreKeyBundle;
import com.sibna.identity.PreKeyPair;
import com.sibna.protocol.DoubleRatchet;
import com.sibna.protocol.X3DHHandshake;
import com.sibna.transport.HttpTransport;
import com.sibna.group.GroupSession;
import com.sibna.exceptions.*;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sibna Protocol Java SDK v3.0.1
 *
 * Ultra-Secure Communication Protocol implementation with:
 * - Ed25519/X25519 identity keys
 * - X3DH handshake for session establishment
 * - Double Ratchet for forward secrecy
 * - ChaCha20-Poly1305 authenticated encryption
 * - Group messaging with sender keys
 * - Safety numbers for identity verification
 */
public class SibnaClient implements AutoCloseable {
    public static final String VERSION = "3.0.1";
    public static final int PROTOCOL_VERSION = 10;

    private final CryptoProvider crypto;
    private final HttpTransport httpTransport;
    private final Map<String, DoubleRatchet> sessions;
    private final Map<String, GroupSession> groups;
    private IdentityKeyPair identity;
    private String jwtToken;
    private volatile boolean closed;

    /**
     * Create a new Sibna client.
     *
     * @param serverUrl The server URL (e.g., "https://sibna.example.com")
     */
    public SibnaClient(String serverUrl) {
        this.crypto = new CryptoProvider();
        this.httpTransport = new HttpTransport(serverUrl);
        this.sessions = new ConcurrentHashMap<>();
        this.groups = new ConcurrentHashMap<>();
    }

    /**
     * Generate a new identity key pair.
     */
    public IdentityKeyPair generateIdentity() throws SibnaException {
        ensureOpen();
        this.identity = IdentityKeyPair.generate(crypto);
        return identity;
    }

    /**
     * Load an identity from a seed.
     */
    public IdentityKeyPair loadIdentity(byte[] seed) throws SibnaException {
        ensureOpen();
        if (seed == null || seed.length != 32) {
            throw new InvalidArgumentException("Seed must be 32 bytes");
        }
        this.identity = IdentityKeyPair.fromSeed(crypto, seed);
        return identity;
    }

    /**
     * Get the current identity (if loaded).
     */
    public Optional<IdentityKeyPair> getIdentity() {
        return Optional.ofNullable(identity);
    }

    /**
     * Authenticate with the server using Ed25519 challenge-response.
     */
    public String authenticate() throws SibnaException {
        ensureOpen();
        if (identity == null) {
            throw new AuthException("No identity loaded");
        }

        // Step 1: Request challenge
        byte[] challenge = httpTransport.requestChallenge(identity.getPublicKeyHex());

        // Step 2: Sign challenge
        byte[] signature = identity.sign(challenge);

        // Step 3: Prove ownership
        this.jwtToken = httpTransport.proveOwnership(
            identity.getPublicKeyHex(),
            challenge,
            signature
        );

        return jwtToken;
    }

    /**
     * Create a new session with a peer using X3DH.
     */
    public DoubleRatchet createSession(String peerId, PreKeyBundle peerBundle) throws SibnaException {
        ensureOpen();
        if (identity == null) {
            throw new AuthException("No identity loaded");
        }

        // Perform X3DH handshake
        X3DHHandshake handshake = new X3DHHandshake(crypto, identity);
        byte[] sharedSecret = handshake.initiate(peerBundle);

        // Initialize Double Ratchet
        DoubleRatchet ratchet = new DoubleRatchet(crypto, sharedSecret, true);
        sessions.put(peerId, ratchet);

        return ratchet;
    }

    /**
     * Accept an incoming session request.
     *
     * <p>FIX: Phase 2.1 — The previous signature did not accept the
     * local signed prekey, so the X3DH responder silently derived a
     * different shared secret from the initiator&apos;s. The local
     * signed prekey is now a required parameter.
     */
    public DoubleRatchet acceptSession(String peerId, byte[] ephemeralPublicKey,
                                        byte[] identityPublicKey, byte[] prekey,
                                        PreKeyPair localSignedPrekey) throws SibnaException {
        ensureOpen();
        if (identity == null) {
            throw new AuthException("No identity loaded");
        }
        if (localSignedPrekey == null) {
            throw new AuthException("Local signed prekey is required for acceptSession()");
        }

        // Perform X3DH handshake as responder
        X3DHHandshake handshake = new X3DHHandshake(crypto, identity, localSignedPrekey);
        byte[] sharedSecret = handshake.respond(ephemeralPublicKey, identityPublicKey, prekey);

        // Initialize Double Ratchet
        DoubleRatchet ratchet = new DoubleRatchet(crypto, sharedSecret, false);
        sessions.put(peerId, ratchet);

        return ratchet;
    }

    /**
     * Encrypt a message for a peer.
     */
    public byte[] encryptMessage(String peerId, byte[] plaintext) throws SibnaException {
        ensureOpen();
        DoubleRatchet ratchet = sessions.get(peerId);
        if (ratchet == null) {
            throw new SessionException("No session found for peer: " + peerId);
        }
        return ratchet.encrypt(plaintext);
    }

    /**
     * Decrypt a message from a peer.
     */
    public byte[] decryptMessage(String peerId, byte[] ciphertext) throws SibnaException {
        ensureOpen();
        DoubleRatchet ratchet = sessions.get(peerId);
        if (ratchet == null) {
            throw new SessionException("No session found for peer: " + peerId);
        }
        return ratchet.decrypt(ciphertext);
    }

    /**
     * Send a sealed message via HTTP.
     */
    public void sendMessage(String recipientId, byte[] ciphertext) throws SibnaException {
        ensureOpen();
        if (jwtToken == null) {
            throw new AuthException("Not authenticated");
        }
        httpTransport.sendMessage(recipientId, ciphertext, jwtToken);
    }

    /**
     * Create a new group.
     */
    public GroupSession createGroup(byte[] groupId) throws SibnaException {
        ensureOpen();
        if (identity == null) {
            throw new AuthException("No identity loaded");
        }

        GroupSession group = new GroupSession(crypto, groupId, identity);
        groups.put(Utils.bytesToHex(groupId), group);
        return group;
    }

    /**
     * Encrypt a group message, returning raw bytes (chain_index || ciphertext).
     */
    public byte[] encryptGroupMessage(byte[] groupId, byte[] plaintext) throws SibnaException {
        ensureOpen();
        GroupSession group = groups.get(Utils.bytesToHex(groupId));
        if (group == null) {
            throw new SessionException("No group found for ID");
        }
        try {
            GroupSession.SenderKeyMessage msg = group.encrypt(plaintext);
            return msg.toBytes();
        } catch (CryptoException e) {
            throw new SibnaException("Group encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt a group message from raw bytes (chain_index || ciphertext).
     */
    public byte[] decryptGroupMessage(byte[] groupId, String senderIdentityHex,
                                       byte[] messageBytes) throws SibnaException {
        ensureOpen();
        GroupSession group = groups.get(Utils.bytesToHex(groupId));
        if (group == null) {
            throw new SessionException("No group found for ID");
        }
        try {
            GroupSession.SenderKeyMessage msg = GroupSession.SenderKeyMessage.fromBytes(messageBytes);
            return group.decrypt(senderIdentityHex, msg);
        } catch (CryptoException e) {
            throw new SibnaException("Group decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Get a group by ID.
     */
    public Optional<GroupSession> getGroup(byte[] groupId) {
        return Optional.ofNullable(groups.get(Utils.bytesToHex(groupId)));
    }

    /**
     * Get a session by peer ID.
     */
    public Optional<DoubleRatchet> getSession(String peerId) {
        return Optional.ofNullable(sessions.get(peerId));
    }

    /**
     * Get the JWT token.
     */
    public Optional<String> getJwtToken() {
        return Optional.ofNullable(jwtToken);
    }

    /**
     * Check if authenticated.
     */
    public boolean isAuthenticated() {
        return jwtToken != null;
    }

    /**
     * Check if a session exists with a peer.
     */
    public boolean hasSession(String peerId) {
        return sessions.containsKey(peerId);
    }

    /**
     * Get the number of active sessions.
     */
    public int getSessionCount() {
        return sessions.size();
    }

    /**
     * Get the number of active groups.
     */
    public int getGroupCount() {
        return groups.size();
    }

    /**
     * Remove a session.
     */
    public void removeSession(String peerId) {
        DoubleRatchet removed = sessions.remove(peerId);
        if (removed != null) {
            removed.close();
        }
    }

    /**
     * Leave and remove a group.
     */
    public void leaveGroup(byte[] groupId) {
        GroupSession removed = groups.remove(Utils.bytesToHex(groupId));
        if (removed != null) {
            removed.leave();
        }
    }

    @Override
    public void close() {
        closed = true;

        // Close all sessions
        for (DoubleRatchet ratchet : sessions.values()) {
            ratchet.close();
        }
        sessions.clear();

        // Close all groups
        for (GroupSession group : groups.values()) {
            group.leave();
        }
        groups.clear();

        // Clear identity
        if (identity != null) {
            identity.clear();
            identity = null;
        }

        // Clear JWT token
        jwtToken = null;
    }

    private void ensureOpen() throws SibnaException {
        if (closed) {
            throw new SibnaException("Client is closed");
        }
    }
}
