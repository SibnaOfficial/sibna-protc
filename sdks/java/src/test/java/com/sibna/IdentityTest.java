package com.sibna;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;

public class IdentityTest {
    private CryptoProvider crypto;

    @BeforeEach
    public void setUp() {
        crypto = new CryptoProvider();
    }

    @Test
    public void testGenerateIdentity() throws CryptoException {
        IdentityKeyPair identity = IdentityKeyPair.generate(crypto);
        assertNotNull(identity);
        assertNotNull(identity.getX25519PublicKey());
        // X25519 public key in JCA PKIX encoding is 44 bytes (12-byte ASN.1 header + 32 raw key)
        assertTrue(identity.getX25519PublicKey().getEncoded().length >= 32);
    }

    @Test
    public void testSignAndVerify() throws CryptoException {
        IdentityKeyPair identity = IdentityKeyPair.generate(crypto);
        byte[] data = "test data".getBytes();
        
        byte[] signature = identity.sign(data);
        assertNotNull(signature);
        assertEquals(64, signature.length);
        
        boolean isValid = identity.verify(data, signature);
        assertTrue(isValid, "Signature should be valid for original data");
        
        byte[] tamperedData = "wrong data".getBytes();
        boolean isInvalid = identity.verify(tamperedData, signature);
        assertFalse(isInvalid, "Signature should be invalid for tampered data");
    }

    @Test
    public void testIdentityFromSeed() throws CryptoException, com.sibna.exceptions.InvalidArgumentException {
        byte[] seed = new byte[32];
        for(int i=0; i<32; i++) seed[i] = (byte)i;
        
        IdentityKeyPair identity1 = IdentityKeyPair.fromSeed(crypto, seed);
        IdentityKeyPair identity2 = IdentityKeyPair.fromSeed(crypto, seed);
        
        assertArrayEquals(identity1.getX25519PublicKey().getEncoded(), identity2.getX25519PublicKey().getEncoded(), "Identities from same seed must match");
    }
}
