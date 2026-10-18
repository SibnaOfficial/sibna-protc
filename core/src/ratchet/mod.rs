//! Double Ratchet (Signal spec: https://signal.org/docs/specifications/doubleratchet/)

pub(crate) mod chain;
pub mod session;
pub mod state;

pub use chain::*;
pub use session::*;
pub use state::*;

use crate::error::{ProtocolError, ProtocolResult};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_SKIPPED_MESSAGES: usize = 2000;
pub const MAX_MESSAGE_KEY_AGE_SECS: u64 = 86400;

/// Plaintext header size: dh_public(32) || message_number(8) || previous_chain_length(8) || timestamp(8)
pub const HEADER_SIZE: usize = 56;

/// Encrypted header nonce size (ChaCha20-Poly1305)
pub const ENCRYPTED_HEADER_NONCE_SIZE: usize = 12;

/// Encrypted header size: nonce(12) || encrypted_header(56) || poly1305_tag(16)
pub const ENCRYPTED_HEADER_SIZE: usize = ENCRYPTED_HEADER_NONCE_SIZE + HEADER_SIZE + 16;

/// Protocol version for v3.1 (header encryption enabled)
pub const PROTOCOL_VERSION_V3_1: u32 = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetHeader {
    pub dh_public: [u8; 32],
    pub message_number: u64,
    pub previous_chain_length: u64,
    pub timestamp: u64,
}

impl RatchetHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(&self.dh_public);
        out.extend_from_slice(&self.message_number.to_le_bytes());
        out.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(ProtocolError::InvalidMessage);
        }
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[0..32]);
        Ok(Self {
            dh_public,
            message_number: u64::from_le_bytes(
                data[32..40]
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidMessage)?,
            ),
            previous_chain_length: u64::from_le_bytes(
                data[40..48]
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidMessage)?,
            ),
            timestamp: u64::from_le_bytes(
                data[48..56]
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidMessage)?,
            ),
        })
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.dh_public.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidMessage);
        }
        if self.message_number > 1_000_000_000_000 {
            return Err(ProtocolError::InvalidMessage);
        }
        // Reject a zero timestamp: it carries no authenticated creation time
        // and must not be accepted as a legitimate message.
        if self.timestamp == 0 {
            return Err(ProtocolError::InvalidMessage);
        }
        let now = crate::crypto::current_timestamp()?;
        // Reject messages more than 5 minutes in the future (clock skew
        // tolerance only). A message stamped in the future cannot have been
        // authentically created yet.
        if self.timestamp > now + 300 {
            return Err(ProtocolError::MessageFromFuture);
        }
        // NOTE: deliberately NO past-age rejection here. A legitimately delayed
        // message (offline queue, store-and-forward, reconnect replay) must be
        // decryptable regardless of how old its authenticated creation
        // timestamp is. Expiration is enforced server-side by the queue TTL
        // (7 days), and replay is prevented by per-session message-number
        // tracking, not by wall-clock age. Rejecting by absolute age here
        // would break delayed delivery and punish slow/restricted links.
        Ok(())
    }

    /// Encrypt the header using a key derived from the chain key.
    /// Wire format: nonce(12) || encrypted_header(56) || tag(16)
    pub fn encrypt(&self, header_key: &[u8; 32]) -> ProtocolResult<Vec<u8>> {
        use crate::crypto::SecureRandom;
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

        let cipher = ChaCha20Poly1305::new(header_key.into());
        let mut rng = SecureRandom::new().map_err(|_| ProtocolError::InternalError)?;
        let mut nonce_bytes = [0u8; ENCRYPTED_HEADER_NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);

        let plaintext = self.to_bytes();
        let encrypted = cipher
            .encrypt(&nonce_bytes.into(), plaintext.as_ref())
            .map_err(|_| ProtocolError::EncryptionFailed)?;

        let mut out = Vec::with_capacity(ENCRYPTED_HEADER_NONCE_SIZE + encrypted.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    /// Decrypt an encrypted header using a key derived from the chain key.
    /// Wire format: nonce(12) || encrypted_header(56) || tag(16)
    pub fn decrypt(data: &[u8], header_key: &[u8; 32]) -> ProtocolResult<Self> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

        if data.len() < ENCRYPTED_HEADER_NONCE_SIZE + 16 {
            return Err(ProtocolError::InvalidMessage);
        }

        let cipher = ChaCha20Poly1305::new(header_key.into());
        let nonce = &data[..ENCRYPTED_HEADER_NONCE_SIZE];
        let ciphertext = &data[ENCRYPTED_HEADER_NONCE_SIZE..];

        let plaintext = cipher
            .decrypt(nonce.into(), ciphertext)
            .map_err(|_| ProtocolError::DecryptionFailed)?;

        Self::from_bytes(&plaintext)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkippedMessageKey {
    pub key: [u8; 32],
    pub created_at: u64,
    pub message_number: u64,
}

impl Drop for SkippedMessageKey {
    fn drop(&mut self) {
        // SECURITY FIX: Zeroize secret message key material on drop.
        // Previously the key bytes remained in heap memory after eviction.
        self.key.zeroize();
    }
}

impl Zeroize for SkippedMessageKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for SkippedMessageKey {}

impl SkippedMessageKey {
    pub fn new(key: [u8; 32], message_number: u64) -> Self {
        Self {
            key,
            message_number,
            created_at: crate::crypto::current_timestamp().unwrap_or(0),
        }
    }

    pub fn is_expired(&self) -> bool {
        crate::crypto::current_timestamp().unwrap_or(self.created_at)
            > self.created_at + MAX_MESSAGE_KEY_AGE_SECS
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    /// Serialize to wire format (plaintext header, for backward compatibility).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_bytes();
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Serialize to wire format with encrypted header (v3.1+).
    /// Wire format: encrypted_header(84) || ciphertext(...)
    pub fn to_bytes_encrypted(&self, header_key: &[u8; 32]) -> ProtocolResult<Vec<u8>> {
        let encrypted_header = self.header.encrypt(header_key)?;
        let mut out = encrypted_header;
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Deserialize from wire format (plaintext header, for backward compatibility).
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < HEADER_SIZE + 29 {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(Self {
            header: RatchetHeader::from_bytes(&data[..HEADER_SIZE])?,
            ciphertext: data[HEADER_SIZE..].to_vec(),
        })
    }

    /// Deserialize from wire format with encrypted header (v3.1+).
    /// Wire format: encrypted_header(84) || ciphertext(...)
    pub fn from_bytes_encrypted(data: &[u8], header_key: &[u8; 32]) -> ProtocolResult<Self> {
        if data.len() < ENCRYPTED_HEADER_SIZE + 29 {
            return Err(ProtocolError::InvalidMessage);
        }
        let header = RatchetHeader::decrypt(&data[..ENCRYPTED_HEADER_SIZE], header_key)?;
        let ciphertext = data[ENCRYPTED_HEADER_SIZE..].to_vec();
        Ok(Self { header, ciphertext })
    }

    /// Check if a message starts with an encrypted header (magic bytes heuristic).
    /// Encrypted headers have random nonce bytes; we use the minimum length check.
    pub fn is_encrypted_header(data: &[u8]) -> bool {
        data.len() >= ENCRYPTED_HEADER_SIZE + 29
    }

    pub fn size(&self) -> usize {
        HEADER_SIZE + self.ciphertext.len()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetStateSummary {
    pub sending_index: u64,
    pub receiving_index: u64,
    pub skipped_keys: usize,
    pub ratchet_count: u64,
}

#[derive(Clone, Debug)]
pub struct StateSummary {
    pub sending_index: u64,
    pub skipped_keys: usize,
}

// Compatibility re-export: the rich StateSummary (in state.rs) carries the
// fields session.rs needs. This alias keeps callers using `super::StateSummary`
// working while pointing at the same type.
pub use state::StateSummary as StateSummaryDetail;

/// Tunable ratchet-level parameters. Currently a thin shim; future fields
/// (DH rotation interval, max chain length, etc.) will land here.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RatchetConfig {
    pub max_skipped_messages: usize,
    pub message_key_max_age_secs: u64,
    pub max_chain_messages: u64,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            max_skipped_messages: MAX_SKIPPED_MESSAGES,
            message_key_max_age_secs: MAX_MESSAGE_KEY_AGE_SECS,
            // Must be >= MAX_SKIPPED_MESSAGES so an adversary cannot force a
            // chain to exhaust before the skipped-key window closes.
            max_chain_messages: (MAX_SKIPPED_MESSAGES as u64) * 2,
        }
    }
}
