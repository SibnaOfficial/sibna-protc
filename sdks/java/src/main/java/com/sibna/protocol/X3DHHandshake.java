package com.sibna.protocol;

import com.sibna.crypto.CryptoProvider;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.identity.PreKeyBundle;
import com.sibna.identity.PreKeyPair;
import com.sibna.exceptions.CryptoException;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * X3DH (Extended Triple Diffie-Hellman) Key Agreement — Sibna Protocol v3.0.1.
 *
 * Transcript binding uses SHA-256 (portable substitute for blake3):
 *   transcript_hash = SHA-256(peer_identity || peer_ephemeral || local_identity || local_prekey || [peer_opk])
 *   shared_secret = HKDF(salt=transcript_hash, ikm=dh1||dh2||dh3||[dh4], info="SibnaX3DH_TranscriptBind_v3", L=32)
 *
 * DH operations:
 *   Initiator: DH1 = IK_a * SPK_b, DH2 = EK_a * IK_b, DH3 = EK_a * SPK_b, [DH4 = EK_a * OPK_b]
 *   Responder: DH1 = SPK_b * IK_a, DH2 = IK_b * EK_a, DH3 = SPK_b * EK_a
 */
public class X3DHHandshake {
    private static final byte[] HKDF_INFO = "SibnaX3DH_TranscriptBind_v3".getBytes();

    private final CryptoProvider crypto;
    private final IdentityKeyPair identity;
    private final PreKeyPair signedPrekey;

    public X3DHHandshake(CryptoProvider crypto, IdentityKeyPair identity, PreKeyPair signedPrekey) {
        this.crypto = crypto;
        this.identity = identity;
        this.signedPrekey = signedPrekey;
    }

    public X3DHHandshake(CryptoProvider crypto, IdentityKeyPair identity) {
        this(crypto, identity, null);
    }

    /**
     * Initiate X3DH as Alice (the initiator).
     *
     * @param peerBundle The responder's PreKey bundle
     * @return 32-byte shared secret
     */
    public byte[] initiate(PreKeyBundle peerBundle) throws CryptoException {
        // Generate ephemeral key pair
        KeyPair ephemeralKeyPair = crypto.generateX25519KeyPair();

        // Our identity public key bytes
        byte[] localIdentityPub = extractRawPublicKey(identity.getX25519PublicKey());
        // Peer keys
        byte[] peerIdentityPub = peerBundle.getIdentityKey();
        byte[] peerSignedPrekey = peerBundle.getSignedPrekey();

        // DH1: our_ik * peer_spk
        byte[] dh1 = crypto.x25519Agreement(
                identity.getX25519PrivateKey(),
                bytesToPublicKey(peerSignedPrekey));

        // DH2: our_ek * peer_ik
        byte[] dh2 = crypto.x25519Agreement(
                ephemeralKeyPair.getPrivate(),
                bytesToPublicKey(peerIdentityPub));

        // DH3: our_ek * peer_spk
        byte[] dh3 = crypto.x25519Agreement(
                ephemeralKeyPair.getPrivate(),
                bytesToPublicKey(peerSignedPrekey));

        // Optional DH4: our_ek * peer_opk
        byte[] dh4 = null;
        if (peerBundle.hasOnetimePrekey()) {
            dh4 = crypto.x25519Agreement(
                    ephemeralKeyPair.getPrivate(),
                    bytesToPublicKey(peerBundle.getOnetimePrekey()));
        }

        // Compute transcript hash: SHA-256(peer_ik || peer_spk || local_ik || local_ephemeral_pub || [peer_opk])
        byte[] transcriptHash = computeTranscriptHash(
                peerIdentityPub, peerSignedPrekey,
                localIdentityPub, extractRawPublicKey(ephemeralKeyPair.getPublic()),
                peerBundle.hasOnetimePrekey() ? peerBundle.getOnetimePrekey() : null);

        // Combine DH results
        byte[] dhResults = concat(dh1, dh2, dh3);
        if (dh4 != null) {
            dhResults = concat(dhResults, dh4);
        }

        // Derive shared secret: HKDF(salt=transcript_hash, ikm=dh_results, info="SibnaX3DH_TranscriptBind_v3")
        byte[] sharedSecret = crypto.hkdf(transcriptHash, dhResults, HKDF_INFO, 32);

        // Clear sensitive data
        clear(dh1, dh2, dh3, dh4, dhResults, transcriptHash);
        return sharedSecret;
    }

    /**
     * Respond to X3DH as Bob (the responder).
     *
     * @param ephemeralPublicKey Alice's ephemeral X25519 public key (raw 32 bytes)
     * @param identityPublicKey  Alice's identity X25519 public key (raw 32 bytes)
     * @param prekey             Alice's signed prekey (unused, for protocol compatibility)
     */
    public byte[] respond(byte[] ephemeralPublicKey, byte[] identityPublicKey, byte[] prekey)
            throws CryptoException {
        if (signedPrekey == null) {
            throw new CryptoException(
                    "X3DHHandshake.respond() requires a local signed prekey; " +
                    "use the (crypto, identity, signedPrekey) constructor.");
        }

        // Our identity and signed prekey public key bytes
        byte[] localIdentityPub = extractRawPublicKey(identity.getX25519PublicKey());
        byte[] localSignedPrekeyPub = extractRawPublicKey(signedPrekey.getPublicKey());

        // DH1: our_spk * peer_ik
        byte[] dh1 = crypto.x25519Agreement(
                signedPrekey.getPrivateKey(),
                bytesToPublicKey(identityPublicKey));

        // DH2: our_ik * peer_ek
        byte[] dh2 = crypto.x25519Agreement(
                identity.getX25519PrivateKey(),
                bytesToPublicKey(ephemeralPublicKey));

        // DH3: our_spk * peer_ek
        byte[] dh3 = crypto.x25519Agreement(
                signedPrekey.getPrivateKey(),
                bytesToPublicKey(ephemeralPublicKey));

        // Compute transcript hash: SHA-256(peer_ik || peer_ek || local_ik || local_spk)
        byte[] transcriptHash = computeTranscriptHash(
                identityPublicKey, ephemeralPublicKey,
                localIdentityPub, localSignedPrekeyPub,
                null);

        byte[] dhResults = concat(dh1, dh2, dh3);

        byte[] sharedSecret = crypto.hkdf(transcriptHash, dhResults, HKDF_INFO, 32);

        clear(dh1, dh2, dh3, dhResults, transcriptHash);
        return sharedSecret;
    }

    /**
     * Compute transcript hash: SHA-256(peer_ik || peer_ephemeral || local_ik || local_prekey || [peer_opk])
     * Portable substitute for blake3.
     */
    private byte[] computeTranscriptHash(byte[] peerIk, byte[] peerEk,
                                          byte[] localIk, byte[] localPrekey,
                                          byte[] peerOpk) throws CryptoException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(peerIk);
            md.update(peerEk);
            md.update(localIk);
            md.update(localPrekey);
            if (peerOpk != null) {
                md.update(peerOpk);
            }
            return md.digest();
        } catch (Exception e) {
            throw new CryptoException("SHA-256 not available", e);
        }
    }

    private byte[] extractRawPublicKey(java.security.PublicKey publicKey) throws CryptoException {
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null) throw new CryptoException("Cannot extract public key bytes");
        if (encoded.length == 32) return encoded;
        if (encoded.length == 44) return Arrays.copyOfRange(encoded, 12, 44);
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private java.security.PublicKey bytesToPublicKey(byte[] keyBytes) throws CryptoException {
        try {
            byte[] x509Prefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
                                  0x6e, 0x03, 0x21, 0x00};
            byte[] x509 = new byte[x509Prefix.length + 32];
            System.arraycopy(x509Prefix, 0, x509, 0, x509Prefix.length);
            System.arraycopy(keyBytes, 0, x509, x509Prefix.length, 32);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("X25519", "BC");
            return kf.generatePublic(new java.security.spec.X509EncodedKeySpec(x509));
        } catch (Exception e) {
            throw new CryptoException("Failed to decode X25519 public key", e);
        }
    }

    private byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] arr : arrays) {
            if (arr != null) totalLen += arr.length;
        }
        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] arr : arrays) {
            if (arr != null) {
                System.arraycopy(arr, 0, result, offset, arr.length);
                offset += arr.length;
            }
        }
        return result;
    }

    private void clear(byte[]... arrays) {
        for (byte[] arr : arrays) {
            if (arr != null) java.util.Arrays.fill(arr, (byte) 0);
        }
    }
}
