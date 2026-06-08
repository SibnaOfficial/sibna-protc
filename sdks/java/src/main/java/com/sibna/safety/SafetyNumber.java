package com.sibna.safety;

import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Safety Number - Human-readable 80-digit fingerprint for identity verification.
 *
 * Derived from both parties' X25519 public keys via SHA-512.
 * Displays as groups of 5 digits separated by spaces.
 * QR data is 36 bytes: version(1) + "SB1"(3) + fingerprint(32).
 */
public class SafetyNumber {
    private static final byte VERSION = 1;
    private static final byte[] DOMAIN = "SIBNA_SAFETY_NUMBER_V1".getBytes();

    private final String digits;
    private final byte[] fingerprint;
    private final byte version;

    private SafetyNumber(byte version, String digits, byte[] fingerprint) {
        this.version = version;
        this.digits = digits;
        this.fingerprint = fingerprint;
    }

    /**
     * Calculate safety number from two 32-byte identity keys.
     * Order-independent: sorts keys lexicographically before hashing.
     */
    public static SafetyNumber calculate(byte[] ourIdentity, byte[] theirIdentity) throws CryptoException {
        byte[] first, second;
        if (Arrays.compare(ourIdentity, theirIdentity) <= 0) {
            first = ourIdentity;
            second = theirIdentity;
        } else {
            first = theirIdentity;
            second = ourIdentity;
        }

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(new byte[]{VERSION});
            md.update(DOMAIN);
            md.update(first);
            md.update(second);
            byte[] hash = md.digest();

            byte[] fp = Arrays.copyOfRange(hash, 0, 32);
            String d = bytesTo80Digits(fp);
            return new SafetyNumber(VERSION, d, fp);
        } catch (Exception e) {
            throw new CryptoException("SHA-512 not available", e);
        }
    }

    /**
     * Convert 32 bytes to 80 decimal digits.
     * Each 2-byte chunk (16 bits, max 65535) → 5 digits, 16 chunks = 80 digits.
     * Groups of 3 chunks (15 digits) separated by spaces.
     */
    private static String bytesTo80Digits(byte[] fp) {
        StringBuilder sb = new StringBuilder(95);
        for (int i = 0; i < 16; i++) {
            int val = ((fp[i * 2] & 0xFF) << 8) | (fp[i * 2 + 1] & 0xFF);
            if (i > 0 && i % 3 == 0) sb.append(' ');
            sb.append(String.format("%05d", val));
        }
        return sb.toString();
    }

    /** Get the 80-digit display string (with spaces). */
    public String asString() { return digits; }

    /** Get raw 32-byte fingerprint. */
    public byte[] fingerprint() { return Arrays.copyOf(fingerprint, 32); }

    /** Get QR data: version(1) + "SB1"(3) + fingerprint(32) = 36 bytes. */
    public byte[] qrData() {
        byte[] data = new byte[36];
        data[0] = version;
        data[1] = 'S'; data[2] = 'B'; data[3] = '1';
        System.arraycopy(fingerprint, 0, data, 4, 32);
        return data;
    }

    /** Constant-time comparison of fingerprints. */
    public boolean verify(SafetyNumber other) {
        if (other == null) return false;
        return constantTimeEquals(this.fingerprint, other.fingerprint);
    }

    /** Parse an 80-digit string back into a SafetyNumber. */
    public static SafetyNumber parse(String s) {
        if (s == null) return null;
        String digitsOnly = s.replaceAll("[^0-9]", "");
        if (digitsOnly.length() != 80) return null;

        byte[] fp = new byte[32];
        for (int i = 0; i < 16; i++) {
            String chunk = digitsOnly.substring(i * 5, i * 5 + 5);
            int val = Integer.parseInt(chunk);
            fp[i * 2]     = (byte) ((val >> 8) & 0xFF);
            fp[i * 2 + 1] = (byte) (val & 0xFF);
        }
        String d = bytesTo80Digits(fp);
        return new SafetyNumber(VERSION, d, fp);
    }

    /** Similarity score (0.0-1.0) for typo detection. */
    public double similarity(SafetyNumber other) {
        if (other == null) return 0.0;
        String a = this.digits.replace(" ", "");
        String b = other.digits.replace(" ", "");
        int matches = 0;
        int len = Math.min(a.length(), b.length());
        for (int i = 0; i < len; i++) {
            if (a.charAt(i) == b.charAt(i)) matches++;
        }
        return (double) matches / 80.0;
    }

    public byte version() { return version; }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
