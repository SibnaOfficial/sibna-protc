package com.sibna.identity;

import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Ed25519 identity key pair for the Sibna Protocol.
 * This is the user's long-term identity used for authentication and signing.
 */
public class IdentityKeyPair {
    private final CryptoProvider crypto;
    private final KeyPair ed25519KeyPair;
    private final KeyPair x25519KeyPair;
    private final String publicKeyHex;

    private IdentityKeyPair(CryptoProvider crypto, KeyPair ed25519, KeyPair x25519) {
        this.crypto = crypto;
        this.ed25519KeyPair = ed25519;
        this.x25519KeyPair = x25519;
        this.publicKeyHex = bytesToHex(ed25519.getPublic().getEncoded());
    }

    /**
     * Generate a new random identity key pair.
     */
    public static IdentityKeyPair generate(CryptoProvider crypto) throws CryptoException {
        KeyPair ed25519 = crypto.generateEd25519KeyPair();
        KeyPair x25519 = crypto.generateX25519KeyPair();
        return new IdentityKeyPair(crypto, ed25519, x25519);
    }

    /**
     * Load an identity from a 32-byte seed using HKDF derivation.
     *
     * FIX: Old implementation derived ed25519Seed and x25519Seed via HKDF
     * correctly, but then discarded them and called generateEd25519KeyPair()
     * (random), making the method non-deterministic. The seed was silently ignored.
     * Now the derived seeds are actually passed to the key factories.
     */
    public static IdentityKeyPair fromSeed(CryptoProvider crypto, byte[] seed) throws CryptoException, com.sibna.exceptions.InvalidArgumentException {
        if (seed == null || seed.length != 32) {
            throw new com.sibna.exceptions.InvalidArgumentException("Seed must be exactly 32 bytes");
        }
        byte[] ed25519Seed = crypto.hkdf(null, seed, "sibna_ed25519_v3".getBytes(java.nio.charset.StandardCharsets.UTF_8), 32);
        byte[] x25519Seed  = crypto.hkdf(null, seed, "sibna_x25519_v3".getBytes(java.nio.charset.StandardCharsets.UTF_8), 32);

        KeyPair ed25519 = crypto.generateEd25519KeyPairFromSeed(ed25519Seed);
        KeyPair x25519  = crypto.generateX25519KeyPairFromSeed(x25519Seed);

        // Zero the intermediate seeds immediately after use
        java.util.Arrays.fill(ed25519Seed, (byte) 0);
        java.util.Arrays.fill(x25519Seed,  (byte) 0);

        return new IdentityKeyPair(crypto, ed25519, x25519);
    }

    /**
     * Get the Ed25519 public key.
     */
    public PublicKey getEd25519PublicKey() {
        return ed25519KeyPair.getPublic();
    }

    /**
     * Get the Ed25519 private key.
     */
    public PrivateKey getEd25519PrivateKey() {
        return ed25519KeyPair.getPrivate();
    }

    /**
     * Get the X25519 public key.
     */
    public PublicKey getX25519PublicKey() {
        return x25519KeyPair.getPublic();
    }

    /**
     * Get the X25519 private key.
     */
    public PrivateKey getX25519PrivateKey() {
        return x25519KeyPair.getPrivate();
    }

    /**
     * Get the public key as hex string.
     */
    public String getPublicKeyHex() {
        return publicKeyHex;
    }

    /**
     * Sign data with Ed25519.
     */
    public byte[] sign(byte[] data) throws CryptoException {
        return crypto.ed25519Sign(ed25519KeyPair.getPrivate(), data);
    }

    /**
     * Verify a signature.
     */
    public boolean verify(byte[] data, byte[] signature) throws CryptoException {
        return crypto.ed25519Verify(ed25519KeyPair.getPublic(), data, signature);
    }

    /**
     * Perform X25519 key agreement with a peer's public key.
     */
    public byte[] x25519Agreement(PublicKey peerPublicKey) throws CryptoException {
        return crypto.x25519Agreement(x25519KeyPair.getPrivate(), peerPublicKey);
    }

    /**
     * Clear sensitive key material.
     */
    public void clear() {
        // Zeroize the encoded form of the keys if possible
        try {
            if (ed25519KeyPair != null && ed25519KeyPair.getPrivate() != null) {
                byte[] encoded = ed25519KeyPair.getPrivate().getEncoded();
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
            if (x25519KeyPair != null && x25519KeyPair.getPrivate() != null) {
                byte[] encoded = x25519KeyPair.getPrivate().getEncoded();
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
        } catch (Exception e) {
            // Best effort - some Key implementations don't support getEncoded()
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
