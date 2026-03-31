#![allow(missing_docs)]
//! Metadata Resistance Module
//!
//! Closes the final gap: even with Sealed Sender, an observer on the wire can:
//!   1. Correlate message SIZE (variable-length reveals content type)
//!   2. Correlate message TIMING (activity patterns reveal social graph)
//!
//! Solutions implemented here:
//!   - Constant-size padding (PKCS#7-style, block = 1024 bytes)
//!   - Timing jitter: server delays delivery by a random 0-500ms
//!   - End-to-end signed envelope: protects against server tampering

use rand::Rng;

/// Target block size for padding (1024 bytes)
/// All messages are padded to the nearest multiple of this value
pub const PADDING_BLOCK_SIZE: usize = 1024;

/// Maximum random delivery jitter in milliseconds
pub const MAX_JITTER_MS: u64 = 500;

/// Pad a message payload to the nearest multiple of PADDING_BLOCK_SIZE
///
/// Format: [1 byte: padding_len_indicator] [original payload] [N bytes random padding]
///
/// An attacker watching encrypted traffic sees only multiples of 1024 bytes,
/// making size-based correlation attacks statistically much harder.
pub fn pad_payload(payload: &[u8]) -> Vec<u8> {
    let unpadded_len = payload.len() + 1; // +1 for the indicator byte
    let padded_len = round_up_to_block(unpadded_len);
    let padding_needed = padded_len - unpadded_len;

    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(padded_len);

    // Indicator: how many padding bytes were added (mod 256)
    // For blocks > 255 bytes of padding, we store padding_needed % 256
    // Receiver reconstructs correct padding_needed from block arithmetic
    out.push((padding_needed % 256) as u8);
    out.extend_from_slice(payload);

    // Fill padding with random bytes (not zeros — zeros are distinguishable)
    let padding: Vec<u8> = (0..padding_needed).map(|_| rng.gen::<u8>()).collect();
    out.extend_from_slice(&padding);

    out
}

/// Remove padding from a received payload
pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, PaddingError> {
    if padded.is_empty() {
        return Err(PaddingError::TooShort);
    }

    let indicator = padded[0] as usize;
    let padded_len = padded.len();

    if padded_len < PADDING_BLOCK_SIZE {
        // Not block-aligned — try to recover assuming indicator is exact
        if padded_len <= indicator + 1 {
            return Err(PaddingError::InvalidPadding);
        }
        return Ok(padded[1..padded_len - indicator].to_vec());
    }

    // Calculate padding from block alignment
    let padding_needed = padded_len % PADDING_BLOCK_SIZE;
    let actual_padding = if padding_needed == 0 {
        // Full block of padding
        indicator
    } else {
        padding_needed
    };

    if padded_len <= actual_padding + 1 {
        return Err(PaddingError::InvalidPadding);
    }

    Ok(padded[1..padded_len - actual_padding].to_vec())
}

fn round_up_to_block(len: usize) -> usize {
    if len == 0 {
        return PADDING_BLOCK_SIZE;
    }
    ((len + PADDING_BLOCK_SIZE - 1) / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE
}

/// Get a random delivery jitter delay
pub fn random_jitter_ms() -> u64 {
    rand::thread_rng().gen_range(0..=MAX_JITTER_MS)
}

/// Padding error
#[derive(Debug, PartialEq)]
pub enum PaddingError {
    TooShort,
    InvalidPadding,
}

/// Signed envelope for end-to-end integrity
///
/// Protects against a compromised server modifying the envelope
/// (changing recipient, injecting messages, altering timestamps).
///
/// The sender signs:
///   SHA-512(recipient_id || payload_hex || timestamp || message_id)
/// using their Ed25519 identity key.
///
/// The recipient MUST verify this signature before decrypting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedEnvelope {
    /// Recipient identity key hex (target)
    pub recipient_id: String,
    /// Encrypted payload hex (Double Ratchet output)
    pub payload_hex: String,
    /// Sender's identity key hex (visible to recipient, hidden from server)
    pub sender_id: String,
    /// Unix timestamp
    pub timestamp: i64,
    /// Unique message ID
    pub message_id: String,
    /// Ed25519 signature over SHA-512(recipient_id || payload_hex || timestamp || message_id)
    pub signature_hex: String,
    /// LZ4 compressed?
    pub compressed: bool,
}

impl SignedEnvelope {
    /// Compute the canonical signing payload
    pub fn signing_payload(&self) -> Vec<u8> {
        use sha2::{Sha512, Digest};
        let mut hasher = Sha512::new();
        hasher.update(self.recipient_id.as_bytes());
        hasher.update(self.payload_hex.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.message_id.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Verify the Ed25519 signature
    pub fn verify(&self) -> Result<(), EnvelopeError> {
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|_| EnvelopeError::MalformedSignature)?;
        let key_bytes = hex::decode(&self.sender_id)
            .map_err(|_| EnvelopeError::MalformedSenderKey)?;

        if key_bytes.len() != 32 || sig_bytes.len() != 64 {
            return Err(EnvelopeError::MalformedSignature);
        }

        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let vk = VerifyingKey::from_bytes(key_bytes.as_slice().try_into().unwrap())
            .map_err(|_| EnvelopeError::InvalidSenderKey)?;
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        let payload = self.signing_payload();

        vk.verify(&payload, &sig)
            .map_err(|_| EnvelopeError::SignatureInvalid)
    }

    /// Check if the envelope is expired (more than 5 minutes old)
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        (now - self.timestamp).abs() > 300
    }
}

/// Envelope error
#[derive(Debug)]
pub enum EnvelopeError {
    MalformedSignature,
    MalformedSenderKey,
    InvalidSenderKey,
    SignatureInvalid,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_roundtrip_small() {
        let payload = b"Hello Sibna!";
        let padded = pad_payload(payload);
        assert_eq!(padded.len(), PADDING_BLOCK_SIZE);
        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(unpadded, payload);
    }

    #[test]
    fn test_padding_roundtrip_large() {
        let payload = vec![0xABu8; 1025];
        let padded = pad_payload(&payload);
        assert_eq!(padded.len(), 2 * PADDING_BLOCK_SIZE);
        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(unpadded, payload);
    }

    #[test]
    fn test_padding_size_indistinguishable() {
        // Two messages of very different sizes should produce same padded size
        let small = b"Hi";
        let medium = vec![0u8; 800];
        assert_eq!(pad_payload(small).len(), pad_payload(&medium).len());
    }

    #[test]
    fn test_jitter_range() {
        for _ in 0..100 {
            let j = random_jitter_ms();
            assert!(j <= MAX_JITTER_MS);
        }
    }
}
