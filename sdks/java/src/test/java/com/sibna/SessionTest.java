package com.sibna;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;
import com.sibna.protocol.DoubleRatchet;
import com.sibna.protocol.DoubleRatchet.Stats;
import com.sibna.protocol.X3DHHandshake;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.identity.PreKeyPair;
import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;
import com.sibna.exceptions.SibnaException;

public class SessionTest {
    private CryptoProvider crypto;
    private byte[] sharedSecret;

    @BeforeEach
    public void setUp() {
        crypto = new CryptoProvider();
        sharedSecret = crypto.generateKey();
    }

    @Test
    public void testSessionEncryptDecryptRoundtrip() throws CryptoException {
        // Setup two parties with the same shared secret
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        DoubleRatchet bob = new DoubleRatchet(crypto, sharedSecret, false);

        byte[] plaintext = "Hello Sibna Production!".getBytes();
        byte[] ad = "associated data".getBytes();

        // Alice encrypts
        byte[] ciphertext = alice.encrypt(plaintext);
        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > plaintext.length);

        // Bob decrypts
        byte[] decrypted = bob.decrypt(ciphertext);
        assertArrayEquals(plaintext, decrypted, "Decrypted plaintext should match original");
    }

    @Test
    public void testSessionReplayProtection() throws CryptoException {
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        DoubleRatchet bob = new DoubleRatchet(crypto, sharedSecret, false);

        byte[] plaintext = "replay test".getBytes();
        byte[] ct = alice.encrypt(plaintext);

        // First decryption should work
        assertDoesNotThrow(() -> bob.decrypt(ct));

        // Second decryption of same ciphertext should fail (replay protection)
        // In DoubleRatchet.java, this happens because receivingMessageNumber increases
        // and the same message number is rejected.
        assertThrows(CryptoException.class, () -> bob.decrypt(ct));
    }

    @Test
    public void testSessionInvalidPlaintext() {
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        
        // Assuming empty plaintext should fail (C++ test does this)
        // Note: We need to implement this check in DoubleRatchet.java if not present.
        byte[] empty = new byte[0];
        assertThrows(Exception.class, () -> alice.encrypt(empty));
    }

    @Test
    public void testSessionShortCiphertext() {
        DoubleRatchet bob = new DoubleRatchet(crypto, sharedSecret, false);
        byte[] shortCt = {0x01, 0x02};
        
        assertThrows(CryptoException.class, () -> bob.decrypt(shortCt));
    }

    @Test
    public void testSessionStats() throws CryptoException {
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        
        Stats statsBefore = alice.getStats();
        assertEquals(0, statsBefore.messagesSent);
        assertEquals(0, statsBefore.messagesReceived);

        alice.encrypt("msg1".getBytes());
        alice.encrypt("msg2".getBytes());

        Stats statsAfter = alice.getStats();
        assertEquals(2, statsAfter.messagesSent);
    }

    @Test
    public void testSessionSerializationRoundtrip() throws CryptoException {
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);

        // Send a message to change state
        alice.encrypt("state change".getBytes());

        byte[] serialized = alice.serialize();
        assertNotNull(serialized);
        assertTrue(serialized.length >= 128);

        DoubleRatchet restored = DoubleRatchet.deserialize(crypto, serialized);

        // Verify restored stats
        assertEquals(alice.getStats().messagesSent, restored.getStats().messagesSent);

        // Verify restored session can still encrypt
        byte[] ct = restored.encrypt("after restore".getBytes());
        assertNotNull(ct);
    }

    /**
     * FIX: Phase 2.1 — proves that the X3DH responder now derives the
     * same shared secret as the initiator. Before the fix, the responder
     * used the identity key for all three DH operations, so the secrets
     * differed and sessions were silently broken.
     *
     * <p>This test is fully self-contained: it re-derives the initiator
     * half of the handshake directly from the same key material so the
     * shared secrets must match if and only if the responder math is
     * correct.
     */
    @Test
    public void testX3DH_responderSharedSecretMatchesInitiator() throws Exception {
        IdentityKeyPair aliceIdentity = IdentityKeyPair.generate(crypto);
        IdentityKeyPair bobIdentity   = IdentityKeyPair.generate(crypto);
        PreKeyPair     bobSignedPrekey = PreKeyPair.generate(crypto);
        java.security.KeyPair aliceEphemeral = crypto.generateX25519KeyPair();

        // Public keys the initiator needs (Bob's IK and SPK)
        java.security.PublicKey bobIdentityPub    = bobIdentity.getX25519PublicKey();
        java.security.PublicKey bobSignedPrekeyPub = bobSignedPrekey.getPublicKey();

        // --- Alice (initiator) side, mirrors X3DHHandshake.initiate() ---
        byte[] dh1 = crypto.x25519Agreement(aliceIdentity.getX25519PrivateKey(), bobSignedPrekeyPub);
        byte[] dh2 = crypto.x25519Agreement(aliceEphemeral.getPrivate(),         bobIdentityPub);
        byte[] dh3 = crypto.x25519Agreement(aliceEphemeral.getPrivate(),         bobSignedPrekeyPub);
        byte[] aliceDhResults = concat(dh1, dh2, dh3);
        byte[] aliceSecret    = crypto.hkdf(null, aliceDhResults, "SibnaProtocol_X3DH".getBytes(), 32);

        // --- Bob (responder) side, via the fixed X3DHHandshake.respond() ---
        X3DHHandshake bobHandshake = new X3DHHandshake(crypto, bobIdentity, bobSignedPrekey);
        byte[] bobSecret = bobHandshake.respond(
            aliceEphemeral.getPublic().getEncoded(),
            aliceIdentity.getX25519PublicKey().getEncoded(),
            bobSignedPrekey.getPublicKeyBytes()
        );

        // Initiator and responder MUST agree on the 32-byte shared secret
        assertEquals(32, aliceSecret.length);
        assertEquals(32, bobSecret.length);
        assertArrayEquals(aliceSecret, bobSecret,
            "X3DH responder must derive the same shared secret as the initiator");
    }

    private static byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] arr : arrays) totalLen += arr.length;
        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }
}
