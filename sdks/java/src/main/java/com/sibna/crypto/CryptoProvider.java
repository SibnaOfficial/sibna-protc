package com.sibna.crypto;

import com.sibna.exceptions.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Cryptographic provider for the Sibna Protocol.
 * Wraps Java's cryptographic primitives to provide the operations needed.
 */
public class CryptoProvider {
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final String CHACHA20_POLY1305 = "ChaCha20-Poly1305";
    private static final String HKDF_ALGORITHM = "HmacSHA256";
    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 16;

    private final SecureRandom secureRandom;

    public CryptoProvider() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generate random bytes.
     */
    public byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generate a 32-byte random key.
     */
    public byte[] generateKey() {
        return randomBytes(KEY_SIZE);
    }

    /**
     * SHA-256 hash.
     */
    public byte[] sha256(byte[] data) throws CryptoException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("SHA-256 not available", e);
        }
    }

    /**
     * SHA-512 hash.
     */
    public byte[] sha512(byte[] data) throws CryptoException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("SHA-512 not available", e);
        }
    }

    /**
     * HMAC-SHA256.
     */
    public byte[] hmacSha256(byte[] key, byte[] data) throws CryptoException {
        try {
            Mac mac = Mac.getInstance(HKDF_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, HKDF_ALGORITHM);
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("HMAC failed", e);
        }
    }

    /**
     * HKDF extract.
     */
    public byte[] hkdfExtract(byte[] salt, byte[] ikm) throws CryptoException {
        if (salt == null || salt.length == 0) {
            salt = new byte[KEY_SIZE];
        }
        return hmacSha256(salt, ikm);
    }

    /**
     * HKDF expand.
     */
    public byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws CryptoException {
        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        int counter = 1;

        while (offset < length) {
            byte[] combined = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, combined, 0, t.length);
            System.arraycopy(info, 0, combined, t.length, info.length);
            combined[combined.length - 1] = (byte) counter;

            t = hmacSha256(prk, combined);
            int toCopy = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, result, offset, toCopy);
            offset += toCopy;
            counter++;
        }

        return result;
    }

    /**
     * HKDF extract and expand.
     */
    public byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) throws CryptoException {
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, length);
    }

    /**
     * Generate an Ed25519 key pair.
     */
    public KeyPair generateEd25519KeyPair() throws CryptoException {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Ed25519 not available", e);
        }
    }

    /**
     * Generate a deterministic Ed25519 key pair from a 32-byte seed.
     * Uses PKCS#8 encoding to import the seed as a private key.
     * FIX: Required by IdentityKeyPair.fromSeed() — was missing.
     */
    /**
     * Generate a deterministic Ed25519 key pair from a 32-byte seed.
     * FIX: Uses BouncyCastle for portable seed-to-keypair derivation across JDK 11-21.
     */
    public KeyPair generateEd25519KeyPairFromSeed(byte[] seed) throws CryptoException {
        if (seed == null || seed.length != 32) {
            throw new CryptoException("Ed25519 seed must be 32 bytes");
        }
        try {
            // Use BouncyCastle — the only portable way to derive Ed25519 pubkey from seed on JDK 11-17
            org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters privParams =
                new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0);
            org.bouncycastle.crypto.params.Ed25519PublicKeyParameters pubParams =
                privParams.generatePublicKey();

            KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");

            // Private key: PKCS#8 via BouncyCastle provider
            byte[] privEncoded = privParams.getEncoded();
            byte[] pkcs8Prefix = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                                   0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };
            byte[] pkcs8 = new byte[pkcs8Prefix.length + privEncoded.length];
            System.arraycopy(pkcs8Prefix, 0, pkcs8, 0, pkcs8Prefix.length);
            System.arraycopy(privEncoded, 0, pkcs8, pkcs8Prefix.length, privEncoded.length);
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

            // Public key: X.509 SubjectPublicKeyInfo
            byte[] pubEncoded = pubParams.getEncoded();
            byte[] x509Prefix = { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
            byte[] x509 = new byte[x509Prefix.length + pubEncoded.length];
            System.arraycopy(x509Prefix, 0, x509, 0, x509Prefix.length);
            System.arraycopy(pubEncoded, 0, x509, x509Prefix.length, pubEncoded.length);
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(x509));

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchProviderException e) {
            throw new CryptoException(
                "BouncyCastle provider not registered. Call: " +
                "Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())", e);
        } catch (Exception e) {
            throw new CryptoException("Ed25519 seed key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Generate a fresh X25519 key pair from a CSPRNG seed.
     * FIX: Phase 2.1 — this no-arg variant was missing; X3DHHandshake.initiate(),
     * DoubleRatchet key ratchets, and IdentityKeyPair.generate() all call it.
     */
    public KeyPair generateX25519KeyPair() throws CryptoException {
        byte[] seed = new byte[32];
        try {
            new java.security.SecureRandom().nextBytes(seed);
            return generateX25519KeyPairFromSeed(seed);
        } finally {
            java.util.Arrays.fill(seed, (byte) 0);
        }
    }

    /**
     * Generate a deterministic X25519 key pair from a 32-byte seed.
     * FIX: Uses BouncyCastle for portable seed-to-keypair derivation.
     */
    public KeyPair generateX25519KeyPairFromSeed(byte[] seed) throws CryptoException {
        if (seed == null || seed.length != 32) {
            throw new CryptoException("X25519 seed must be 32 bytes");
        }
        try {
            org.bouncycastle.crypto.params.X25519PrivateKeyParameters privParams =
                new org.bouncycastle.crypto.params.X25519PrivateKeyParameters(seed, 0);
            org.bouncycastle.crypto.params.X25519PublicKeyParameters pubParams =
                (org.bouncycastle.crypto.params.X25519PublicKeyParameters) privParams.generatePublicKey();

            // Wrap as JCA keys via PKCS#8 / X.509
            byte[] pkcs8Prefix = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                                   0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20 };
            byte[] privEncoded = privParams.getEncoded();
            byte[] pkcs8 = new byte[pkcs8Prefix.length + privEncoded.length];
            System.arraycopy(pkcs8Prefix, 0, pkcs8, 0, pkcs8Prefix.length);
            System.arraycopy(privEncoded, 0, pkcs8, pkcs8Prefix.length, privEncoded.length);
            KeyFactory kf = KeyFactory.getInstance("X25519", "BC");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

            byte[] pubEncoded = pubParams.getEncoded();
            byte[] x509Prefix = { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00 };
            byte[] x509 = new byte[x509Prefix.length + pubEncoded.length];
            System.arraycopy(x509Prefix, 0, x509, 0, x509Prefix.length);
            System.arraycopy(pubEncoded, 0, x509, x509Prefix.length, pubEncoded.length);
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(x509));

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchProviderException e) {
            throw new CryptoException(
                "BouncyCastle provider not registered. Call: " +
                "Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())", e);
        } catch (Exception e) {
            throw new CryptoException("X25519 seed key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * X25519 key agreement.

     */
    public byte[] x25519Agreement(PrivateKey privateKey, PublicKey publicKey) throws CryptoException {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(privateKey);
            ka.doPhase(publicKey, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new CryptoException("X25519 agreement failed", e);
        }
    }

    /**
     * Ed25519 sign.
     */
    public byte[] ed25519Sign(PrivateKey privateKey, byte[] data) throws CryptoException {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new CryptoException("Ed25519 sign failed", e);
        }
    }

    /**
     * Ed25519 verify.
     */
    public boolean ed25519Verify(PublicKey publicKey, byte[] data, byte[] signature) throws CryptoException {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            throw new CryptoException("Ed25519 verify failed", e);
        }
    }

    /**
     * ChaCha20-Poly1305 encrypt.
     */
    public byte[] encrypt(byte[] key, byte[] plaintext, byte[] associatedData) throws CryptoException {
        try {
            byte[] nonce = randomBytes(NONCE_SIZE);
            Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, nonce);
            SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }

            byte[] ciphertext = cipher.doFinal(plaintext);

            // Combine: nonce || ciphertext || tag
            byte[] result = new byte[NONCE_SIZE + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, NONCE_SIZE);
            System.arraycopy(ciphertext, 0, result, NONCE_SIZE, ciphertext.length);

            return result;
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    /**
     * ChaCha20-Poly1305 decrypt.
     */
    public byte[] decrypt(byte[] key, byte[] ciphertext, byte[] associatedData) throws CryptoException {
        if (ciphertext.length < NONCE_SIZE + TAG_SIZE) {
            throw new CryptoException("Ciphertext too short");
        }

        try {
            byte[] nonce = Arrays.copyOfRange(ciphertext, 0, NONCE_SIZE);
            byte[] encrypted = Arrays.copyOfRange(ciphertext, NONCE_SIZE, ciphertext.length);

            Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, nonce);
            SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }

            return cipher.doFinal(encrypted);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    /**
     * Validate an X25519 public key against the 8 known low-order points.
     * Rejects keys that would produce a zero DH output (small subgroup attack).
     */
    public boolean validatePublicKey(byte[] pubKey) throws CryptoException {
        if (pubKey == null || pubKey.length != 32) {
            return false;
        }
        // 8 known low-order points for Curve25519
        byte[][] lowOrderPoints = {
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
            {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
            {(byte)0xe0,(byte)0xeb,0x7a,0x7c,0x3b,0x41,(byte)0xb8,0x01,(byte)0xf1,(byte)0xda,
             0x56,0x75,0x47,0x11,(byte)0x85,0x12,0x1a,(byte)0x9f,0x17,0x60,(byte)0xe7,0x61,
             0x19,(byte)0x90,0x3f,0x52,0x49,0x22,(byte)0xfe,(byte)0x80,0x5a,0x5f},
            {0x5f,(byte)0x9c,(byte)0x95,(byte)0xbc,(byte)0xa3,0x50,(byte)0x8c,0x24,(byte)0xb1,
             (byte)0xd0,(byte)0xb1,(byte)0xa5,(byte)0x99,(byte)0x83,0x17,0x0c,0x64,(byte)0x81,
             0x41,(byte)0xb2,0x39,0x52,(byte)0x80,0x24,(byte)0xed,0x54,(byte)0x8f,0x61,0x6c,
             0x7e,0x48,(byte)0x8a},
            {(byte)0xed,(byte)0xce,(byte)0x84,0x43,(byte)0xbc,(byte)0xaf,0x73,0x1d,0x0e,0x25,
             (byte)0xd4,0x7f,0x3d,0x1b,(byte)0xba,(byte)0x8a,(byte)0xb6,(byte)0xb0,0x5b,0x69,
             (byte)0x80,0x45,0x29,(byte)0xed,0x7f,0x72,0x1d,(byte)0x97,(byte)0xa3,0x31,(byte)0xa3,
             (byte)0xec},
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,(byte)0x80},
            {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,(byte)0x81},
            {(byte)0xe0,(byte)0xeb,0x7a,0x7c,0x3b,0x41,(byte)0xb8,0x01,(byte)0xf1,(byte)0xda,
             0x56,0x75,0x47,0x11,(byte)0x85,0x12,0x1a,(byte)0x9f,0x17,0x60,(byte)0xe7,0x61,
             0x19,(byte)0x90,0x3f,0x52,0x49,0x22,(byte)0xfe,(byte)0x80,0x5a,(byte)0xdf}
        };

        for (byte[] point : lowOrderPoints) {
            if (java.util.Arrays.equals(pubKey, point)) {
                return false;
            }
        }
        return true;
    }

    /**
     * ChaCha20-Poly1305 encrypt with structured nonce: random(8) || msg_num_le(4).
     * The nonce is 12 bytes total: 8 random bytes + 4-byte LE message number.
     * Returns: nonce(12) || ciphertext || tag(16)
     */
    public byte[] encryptWithNonceCounter(byte[] key, byte[] plaintext, byte[] associatedData,
                                          int msgNum) throws CryptoException {
        try {
            byte[] randomPart = randomBytes(8);
            byte[] nonce = new byte[12];
            System.arraycopy(randomPart, 0, nonce, 0, 8);
            nonce[8]  = (byte)(msgNum);
            nonce[9]  = (byte)(msgNum >>> 8);
            nonce[10] = (byte)(msgNum >>> 16);
            nonce[11] = (byte)(msgNum >>> 24);

            Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, nonce);
            SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] result = new byte[NONCE_SIZE + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, NONCE_SIZE);
            System.arraycopy(ciphertext, 0, result, NONCE_SIZE, ciphertext.length);
            return result;
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    /**
     * ChaCha20-Poly1305 decrypt with structured nonce: random(8) || msg_num_le(4).
     * Input: nonce(12) || ciphertext || tag(16)
     */
    public byte[] decryptWithNonceCounter(byte[] key, byte[] ciphertextWithNonce, byte[] associatedData) throws CryptoException {
        if (ciphertextWithNonce.length < NONCE_SIZE + TAG_SIZE) {
            throw new CryptoException("Ciphertext too short");
        }
        try {
            byte[] nonce = Arrays.copyOfRange(ciphertextWithNonce, 0, NONCE_SIZE);
            byte[] encrypted = Arrays.copyOfRange(ciphertextWithNonce, NONCE_SIZE, ciphertextWithNonce.length);

            Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, nonce);
            SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }
            return cipher.doFinal(encrypted);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    public int getKeySize() { return KEY_SIZE; }
    public int getNonceSize() { return NONCE_SIZE; }
    public int getTagSize() { return TAG_SIZE; }
}
