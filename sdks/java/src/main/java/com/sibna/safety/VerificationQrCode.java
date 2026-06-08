package com.sibna.safety;

import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * QR-verifiable identity binding with Ed25519 signatures.
 *
 * Wire format (119 bytes):
 *   version(1) || "SIBNA"(5) || verified(1) || identity_key(32) || device_id(16) || fingerprint(32) || signature(32)
 *
 * The signature is Ed25519 over version || "SIBNA" || verified || identity_key || device_id || fingerprint,
 * signed with a dedicated verification key pair derived from the identity.
 */
public class VerificationQrCode {
    private static final byte[] MAGIC = "SIBNA".getBytes();
    private static final int HEADER_SIZE = 1 + 5 + 1 + 32 + 16 + 32; // 87
    private static final int TOTAL_SIZE = HEADER_SIZE + 32; // 119

    private byte version;
    private boolean verified;
    private final byte[] identityKey;
    private final byte[] deviceId;
    private final byte[] safetyFingerprint;
    private byte[] signature;

    private VerificationQrCode(byte version, boolean verified, byte[] identityKey,
                                byte[] deviceId, byte[] safetyFingerprint, byte[] signature) {
        this.version = version;
        this.verified = verified;
        this.identityKey = identityKey;
        this.deviceId = deviceId;
        this.safetyFingerprint = safetyFingerprint;
        this.signature = signature;
    }

    /**
     * Generate a new QR code, signing with the verification private key.
     *
     * @param crypto           crypto provider
     * @param identityKey      32-byte Ed25519/X25519 identity public key
     * @param deviceId         16-byte device identifier
     * @param safetyFingerprint 32-byte safety number fingerprint
     * @param signingKeyPair   Ed25519 key pair used to sign the QR payload
     */
    public static VerificationQrCode generate(CryptoProvider crypto,
                                               byte[] identityKey,
                                               byte[] deviceId,
                                               byte[] safetyFingerprint,
                                               KeyPair signingKeyPair) throws CryptoException {
        byte[] payload = buildPayload((byte) 1, false, identityKey, deviceId, safetyFingerprint);
        byte[] sig = crypto.ed25519Sign(signingKeyPair.getPrivate(), payload);
        return new VerificationQrCode((byte) 1, false,
                Arrays.copyOf(identityKey, 32),
                Arrays.copyOf(deviceId, 16),
                Arrays.copyOf(safetyFingerprint, 32),
                sig);
    }

    /**
     * Verify the QR code signature using the signer's Ed25519 public key.
     */
    public boolean verify(CryptoProvider crypto, PublicKey signerPublicKey) throws CryptoException {
        byte[] payload = buildPayload(version, verified, identityKey, deviceId, safetyFingerprint);
        return crypto.ed25519Verify(signerPublicKey, payload, signature);
    }

    /**
     * Serialize to bytes (119 bytes).
     */
    public byte[] toBytes() {
        byte[] out = new byte[TOTAL_SIZE];
        int off = 0;
        out[off++] = version;
        System.arraycopy(MAGIC, 0, out, off, MAGIC.length); off += MAGIC.length;
        out[off++] = verified ? (byte) 1 : (byte) 0;
        System.arraycopy(identityKey, 0, out, off, 32); off += 32;
        System.arraycopy(deviceId, 0, out, off, 16); off += 16;
        System.arraycopy(safetyFingerprint, 0, out, off, 32); off += 32;
        System.arraycopy(signature, 0, out, off, 32);
        return out;
    }

    /**
     * Deserialize from bytes. Returns null if invalid.
     */
    public static VerificationQrCode fromBytes(byte[] data) {
        if (data == null || data.length != TOTAL_SIZE) return null;
        if (data[0] != 1) return null;
        for (int i = 0; i < 5; i++) {
            if (data[1 + i] != MAGIC[i]) return null;
        }
        byte version = data[0];
        boolean verified = data[6] != 0;
        byte[] ik = Arrays.copyOfRange(data, 7, 39);
        byte[] did = Arrays.copyOfRange(data, 39, 55);
        byte[] fp = Arrays.copyOfRange(data, 55, 87);
        byte[] sig = Arrays.copyOfRange(data, 87, 119);
        return new VerificationQrCode(version, verified, ik, did, fp, sig);
    }

    public void markVerified() { this.verified = true; }
    public boolean isVerified() { return verified; }
    public byte[] identityKey() { return Arrays.copyOf(identityKey, 32); }
    public byte[] deviceId() { return Arrays.copyOf(deviceId, 16); }
    public byte[] safetyFingerprint() { return Arrays.copyOf(safetyFingerprint, 32); }
    public byte[] signature() { return signature != null ? Arrays.copyOf(signature, 32) : null; }
    public byte version() { return version; }

    private static byte[] buildPayload(byte version, boolean verified,
                                         byte[] identityKey, byte[] deviceId, byte[] fingerprint) {
        byte[] payload = new byte[HEADER_SIZE];
        int off = 0;
        payload[off++] = version;
        System.arraycopy(MAGIC, 0, payload, off, MAGIC.length); off += MAGIC.length;
        payload[off++] = (byte)(verified ? 1 : 0);
        System.arraycopy(identityKey, 0, payload, off, 32); off += 32;
        System.arraycopy(deviceId, 0, payload, off, 16); off += 16;
        System.arraycopy(fingerprint, 0, payload, off, 32);
        return payload;
    }
}
