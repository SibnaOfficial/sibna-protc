package com.sibna.protocol;

import com.sibna.crypto.CryptoProvider;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.identity.PreKeyBundle;
import com.sibna.identity.PreKeyPair;
import com.sibna.exceptions.CryptoException;

/**
 * X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol.
 *
 * Performs 3-4 DH operations to establish a shared secret:
 * <ul>
 *   <li>Initiator: DH(IK_a, SPK_b) + DH(EK_a, IK_b) + DH(EK_a, SPK_b) + optional DH(EK_a, OPK_b)</li>
 *   <li>Responder: DH(SPK_b, IK_a) + DH(IK_b, EK_a) + DH(SPK_b, EK_a) + optional DH(OPK_b, EK_a)</li>
 * </ul>
 *
 * <p>FIX: Phase 2.1 — The responder constructor previously received no
 * access to the local signed prekey private half and silently used the
 * identity key for all three DH operations. The fix:
 * <ol>
 *   <li>The constructor now requires the local responder signed prekey.</li>
 *   <li>DH1 and DH3 use the SPK private key (not IK).</li>
 *   <li>DH2 uses the IK private key (unchanged).</li>
 * </ol>
 * The initiator path is unchanged; it never needed the local SPK.
 */
public class X3DHHandshake {
    private final CryptoProvider crypto;
    private final IdentityKeyPair identity;
    private final PreKeyPair signedPrekey;

    /**
     * Full constructor used by the responder.
     *
     * @param crypto        crypto provider
     * @param identity      local long-term identity
     * @param signedPrekey  local signed prekey pair (required for responder,
     *                      may be {@code null} when only {@link #initiate}
     *                      will be invoked on this instance)
     */
    public X3DHHandshake(CryptoProvider crypto, IdentityKeyPair identity, PreKeyPair signedPrekey) {
        this.crypto = crypto;
        this.identity = identity;
        this.signedPrekey = signedPrekey;
    }

    /**
     * Initiator-only convenience constructor.
     *
     * <p>FIX: Phase 2.1 — kept for source-compatibility with the
     * {@code SibnaClient.createSession(...)} path. Calling
     * {@link #respond(byte[], byte[], byte[])} on an instance built
     * with this constructor will throw a {@link CryptoException}.
     */
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
        var ephemeralKeyPair = crypto.generateX25519KeyPair();

        // DH1: our_ik * peer_spk
        byte[] dh1 = crypto.x25519Agreement(
            identity.getX25519PrivateKey(),
            bytesToPublicKey(peerBundle.getSignedPrekey())
        );

        // DH2: our_ek * peer_ik
        byte[] dh2 = crypto.x25519Agreement(
            ephemeralKeyPair.getPrivate(),
            bytesToPublicKey(peerBundle.getIdentityKey())
        );

        // DH3: our_ek * peer_spk
        byte[] dh3 = crypto.x25519Agreement(
            ephemeralKeyPair.getPrivate(),
            bytesToPublicKey(peerBundle.getSignedPrekey())
        );

        // Combine DH results
        byte[] dhResults = concat(dh1, dh2, dh3);

        // Optional DH4: our_ek * peer_opk
        if (peerBundle.hasOnetimePrekey()) {
            byte[] dh4 = crypto.x25519Agreement(
                ephemeralKeyPair.getPrivate(),
                bytesToPublicKey(peerBundle.getOnetimePrekey())
            );
            dhResults = concat(dhResults, dh4);
        }

        // Derive shared secret using HKDF
        byte[] sharedSecret = crypto.hkdf(null, dhResults, "SibnaProtocol_X3DH".getBytes(), 32);

        // Clear sensitive data
        clear(dh1, dh2, dh3);

        return sharedSecret;
    }

    /**
     * Respond to X3DH as Bob (the responder).
     *
     * <p>FIX: Phase 2.1 — DH1 and DH3 used to be computed with
     * {@code identity.getX25519PrivateKey()} (the identity key), so the
     * responder and the initiator derived different shared secrets and
     * sessions were silently broken. The correct responder recipe is:
     * <pre>
     *   DH1 = SPK_B * IK_A     (peer identity public, our signed prekey private)
     *   DH2 = IK_B  * EK_A     (peer ephemeral public, our identity private)
     *   DH3 = SPK_B * EK_A     (peer ephemeral public, our signed prekey private)
     * </pre>
     *
     * @param ephemeralPublicKey  Alice's ephemeral X25519 public key
     * @param identityPublicKey   Alice's identity X25519 public key
     * @param prekey              Alice's signed prekey (unused by the
     *                            responder; accepted for protocol-shape
     *                            compatibility with the calling code)
     */
    public byte[] respond(byte[] ephemeralPublicKey, byte[] identityPublicKey, byte[] prekey) throws CryptoException {
        if (signedPrekey == null) {
            throw new CryptoException(
                "X3DHHandshake.respond() requires a local signed prekey; " +
                "use the (crypto, identity, signedPrekey) constructor."
            );
        }

        // DH1: our_spk * peer_ik
        byte[] dh1 = crypto.x25519Agreement(
            signedPrekey.getPrivateKey(),
            bytesToPublicKey(identityPublicKey)
        );

        // DH2: our_ik * peer_ek
        byte[] dh2 = crypto.x25519Agreement(
            identity.getX25519PrivateKey(),
            bytesToPublicKey(ephemeralPublicKey)
        );

        // DH3: our_spk * peer_ek
        byte[] dh3 = crypto.x25519Agreement(
            signedPrekey.getPrivateKey(),
            bytesToPublicKey(ephemeralPublicKey)
        );

        // Optional DH4: our_opk * peer_ek — only when the peer bundled an OPK
        // (the Java SDK currently does not generate or consume one-time
        // prekeys, so DH4 is always skipped here).
        byte[] dhResults = concat(dh1, dh2, dh3);

        byte[] sharedSecret = crypto.hkdf(null, dhResults, "SibnaProtocol_X3DH".getBytes(), 32);

        clear(dh1, dh2, dh3);

        return sharedSecret;
    }

    private java.security.PublicKey bytesToPublicKey(byte[] keyBytes) throws CryptoException {
        // Simplified - in production, use proper X509 encoding
        try {
            java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("X25519", "BC");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new CryptoException("Failed to decode public key", e);
        }
    }

    private byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] arr : arrays) {
            totalLen += arr.length;
        }
        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }

    private void clear(byte[]... arrays) {
        for (byte[] arr : arrays) {
            if (arr != null) {
                java.util.Arrays.fill(arr, (byte) 0);
            }
        }
    }
}
