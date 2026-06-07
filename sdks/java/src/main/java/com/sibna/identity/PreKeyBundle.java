package com.sibna.identity;

import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;

import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

/**
 * PreKey bundle for X3DH handshake.
 * Contains the identity key, signed prekey, and optional one-time prekey.
 */
public class PreKeyBundle {
    private final byte[] identityKey;
    private final byte[] signedPrekey;
    private final byte[] signature;
    private final byte[] onetimePrekey;
    private final Instant timestamp;

    private PreKeyBundle(byte[] identityKey, byte[] signedPrekey, byte[] signature,
                         byte[] onetimePrekey) {
        this.identityKey = identityKey;
        this.signedPrekey = signedPrekey;
        this.signature = signature;
        this.onetimePrekey = onetimePrekey;
        this.timestamp = Instant.now();
    }

    /**
     * Create a new PreKey bundle signed by the identity key.
     */
    public static PreKeyBundle create(CryptoProvider crypto, IdentityKeyPair identity,
                                      byte[] signedPrekeyPublic, byte[] signature,
                                      byte[] onetimePrekeyPublic) throws CryptoException {
        return new PreKeyBundle(
            identity.getX25519PublicKey().getEncoded(),
            signedPrekeyPublic,
            signature,
            onetimePrekeyPublic
        );
    }

    /**
     * Serialize the bundle to bytes.
     */
    public byte[] toBytes() {
        int totalLen = identityKey.length + signedPrekey.length + signature.length + 1;
        boolean hasOnetime = onetimePrekey != null && onetimePrekey.length > 0;
        if (hasOnetime) {
            totalLen += onetimePrekey.length;
        }

        byte[] result = new byte[totalLen];
        int offset = 0;

        System.arraycopy(identityKey, 0, result, offset, identityKey.length);
        offset += identityKey.length;
        System.arraycopy(signedPrekey, 0, result, offset, signedPrekey.length);
        offset += signedPrekey.length;
        System.arraycopy(signature, 0, result, offset, signature.length);
        offset += signature.length;
        result[offset++] = hasOnetime ? (byte) 1 : (byte) 0;
        if (hasOnetime) {
            System.arraycopy(onetimePrekey, 0, result, offset, onetimePrekey.length);
        }

        return result;
    }

    public boolean hasOnetimePrekey() {
        return onetimePrekey != null && onetimePrekey.length > 0;
    }

    public boolean isExpired() {
        return timestamp.plus(7, ChronoUnit.DAYS).isBefore(Instant.now());
    }

    public byte[] getIdentityKey() { return Arrays.copyOf(identityKey, identityKey.length); }
    public byte[] getSignedPrekey() { return Arrays.copyOf(signedPrekey, signedPrekey.length); }
    public byte[] getSignature() { return Arrays.copyOf(signature, signature.length); }
    public byte[] getOnetimePrekey() {
        return onetimePrekey != null ? Arrays.copyOf(onetimePrekey, onetimePrekey.length) : null;
    }

    public String getIdentityKeyHex() {
        return bytesToHex(identityKey);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
