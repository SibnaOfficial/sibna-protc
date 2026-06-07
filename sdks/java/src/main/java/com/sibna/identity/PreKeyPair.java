package com.sibna.identity;

import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Local signed prekey pair (X25519).
 *
 * <p>The X3DH responder needs both the PUBLIC half (advertised in the
 * PreKey bundle) and the PRIVATE half (kept on the responder device to
 * compute DH1 = SPK_B * IK_A and DH3 = SPK_B * EK_A during the handshake).
 *
 * <p>This is the local counterpart of {@link PreKeyBundle#getSignedPrekey()},
 * which only carries the public half of a peer&apos;s signed prekey.
 *
 * <p>FIX: Phase 2.1 — {@code X3DHHandshake.respond()} previously had no
 * way to access the responder&apos;s signed prekey private key and
 * silently substituted the identity key in all three DH operations. The
 * resulting shared secret was neither equal to the initiator&apos;s
 * shared secret nor to the value produced by the Rust core.
 */
public final class PreKeyPair {
    private final KeyPair x25519KeyPair;

    private PreKeyPair(KeyPair x25519) {
        this.x25519KeyPair = x25519;
    }

    /**
     * Generate a fresh signed prekey pair from a CSPRNG.
     */
    public static PreKeyPair generate(CryptoProvider crypto) throws CryptoException {
        return new PreKeyPair(crypto.generateX25519KeyPair());
    }

    /**
     * Deterministically derive a signed prekey pair from a 32-byte seed.
     * Intended for tests that need reproducible keys.
     */
    public static PreKeyPair fromSeed(CryptoProvider crypto, byte[] seed) throws CryptoException {
        if (seed == null || seed.length != 32) {
            throw new com.sibna.exceptions.InvalidArgumentException("Seed must be exactly 32 bytes");
        }
        return new PreKeyPair(crypto.generateX25519KeyPairFromSeed(seed));
    }

    /**
     * Get the public half (X.509-encoded). Wire-format compatible with
     * {@link PreKeyBundle#getSignedPrekey()}.
     */
    public PublicKey getPublicKey() {
        return x25519KeyPair.getPublic();
    }

    /**
     * Get the private half. Used by the X3DH responder only.
     */
    public PrivateKey getPrivateKey() {
        return x25519KeyPair.getPrivate();
    }

    /**
     * X.509-encoded public key bytes for inclusion in a PreKey bundle.
     */
    public byte[] getPublicKeyBytes() {
        return x25519KeyPair.getPublic().getEncoded();
    }

    /**
     * Best-effort zeroisation of the underlying key material.
     */
    public void clear() {
        try {
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
}
