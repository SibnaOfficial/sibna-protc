//! Double Ratchet Implementation - Hardened Edition
//!
//! This module implements the Double Ratchet algorithm as specified in:
//! https://signal.org/docs/specifications/doubleratchet/
//!
//! # Security Features
//! - Forward secrecy through DH ratchet
//! - Post-compromise security through symmetric ratchet
//! - Out-of-order message handling with secure key storage
//! - Constant-time operations where possible
//! - Automatic key zeroization

mod chain;
mod state;
mod session;

pub use chain::*;
pub use state::*;
pub use session::*;

use x25519_dalek::{PublicKey, StaticSecret};
use std::collections::HashMap;
use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::constant_time_eq;

/// Maximum number of skipped messages to store
pub const MAX_SKIPPED_MESSAGES: usize = 2000;

/// Maximum message key age in seconds (24 hours)
pub const MAX_MESSAGE_KEY_AGE_SECS: u64 = 86400;

/// Header size for Double Ratchet messages (32 DH + 8 msg_num + 8 prev_len + 8 timestamp)
pub const HEADER_SIZE: usize = 32 + 8 + 8 + 8;

/// Ratchet message header
#[derive(Clone, Debug)]
pub struct RatchetHeader {
    /// DH public key
    pub dh_public: [u8; 32],
    /// Message number in current chain
    pub message_number: u64,
    /// Length of previous chain
    pub previous_chain_length: u64,
    /// Timestamp for replay protection
    pub timestamp: u64,
}

impl RatchetHeader {
    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(HEADER_SIZE + 8);
        result.extend_from_slice(&self.dh_public);
        result.extend_from_slice(&self.message_number.to_le_bytes());
        result.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        result.extend_from_slice(&self.timestamp.to_le_bytes());
        result
    }

    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(ProtocolError::InvalidMessage);
        }

        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[0..32]);

        let message_number = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProtocolError::InvalidMessage)?
        );

        let previous_chain_length = u64::from_le_bytes(
            data[40..48].try_into().map_err(|_| ProtocolError::InvalidMessage)?
        );

        let timestamp = if data.len() >= 56 {
            u64::from_le_bytes(
                data[48..56].try_into().map_err(|_| ProtocolError::InvalidMessage)?
            )
        } else {
            0
        };

        Ok(Self {
            dh_public,
            message_number,
            previous_chain_length,
            timestamp,
        })
    }

    /// Validate header for security
    pub fn validate(&self) -> ProtocolResult<()> {
        // Check DH public key is not all zeros
        if self.dh_public.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidMessage);
        }

        // Check message number is reasonable
        if self.message_number > 1_000_000_000_000 {
            return Err(ProtocolError::InvalidMessage);
        }

        // Check timestamp is reasonable
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        // Allow 5 minutes clock skew
        if self.timestamp > now + 300 {
            return Err(ProtocolError::InvalidMessage);
        }

        // Reject messages older than 24 hours
        if self.timestamp > 0 && now > self.timestamp + 86400 {
            return Err(ProtocolError::MessageTooOld);
        }

        Ok(())
    }
}

/// Skipped message key entry with metadata
#[derive(Clone, Debug)]
pub struct SkippedMessageKey {
    /// The message key
    pub key: [u8; 32],
    /// When the key was created
    pub created_at: u64,
    /// Message number
    pub message_number: u64,
}

impl SkippedMessageKey {
    /// Create a new skipped message key
    pub fn new(key: [u8; 32], message_number: u64) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            key,
            created_at,
            message_number,
        }
    }

    /// Check if the key has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > self.created_at + MAX_MESSAGE_KEY_AGE_SECS
    }
}

/// Ratchet message with header and ciphertext
#[derive(Clone, Debug)]
pub struct RatchetMessage {
    /// Message header
    pub header: RatchetHeader,
    /// Encrypted payload (nonce || ciphertext || tag)
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = self.header.to_bytes();
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Parse message from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < HEADER_SIZE + 29 { // header + minimum ciphertext
            return Err(ProtocolError::InvalidMessage);
        }

        let header = RatchetHeader::from_bytes(&data[..HEADER_SIZE])?;
        let ciphertext = data[HEADER_SIZE..].to_vec();

        Ok(Self { header, ciphertext })
    }

    /// Get the total message size
    pub fn size(&self) -> usize {
        HEADER_SIZE + self.ciphertext.len()
    }
}

/// Ratchet state summary (for debugging/monitoring)
#[derive(Clone, Debug)]
pub struct RatchetStateSummary {
    /// Current sending chain index
    pub sending_index: u64,
    /// Current receiving chain index
    pub receiving_index: u64,
    /// Number of skipped message keys
    pub skipped_keys_count: usize,
    /// Whether DH ratchet is pending
    pub dh_ratchet_pending: bool,
    /// Root key fingerprint (first 8 bytes, hashed)
    pub root_key_fingerprint: [u8; 8],
}

/// Ratchet configuration
#[derive(Clone, Debug)]
pub struct RatchetConfig {
    /// Maximum skipped messages
    pub max_skipped_messages: usize,
    /// Maximum message key age in seconds
    pub max_message_key_age_secs: u64,
    /// Enable automatic key pruning
    pub auto_prune_keys: bool,
    /// Enable timestamp validation
    pub validate_timestamps: bool,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            max_skipped_messages: MAX_SKIPPED_MESSAGES,
            max_message_key_age_secs: MAX_MESSAGE_KEY_AGE_SECS,
            auto_prune_keys: true,
            validate_timestamps: true,
        }
    }
}

/// Utility functions for the ratchet module
pub mod utils {
    use super::*;

    /// Generate a new X25519 key pair
    pub fn generate_keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// Perform DH key agreement
    pub fn dh_agree(secret: &StaticSecret, public: &PublicKey) -> [u8; 32] {
        secret.diffie_hellman(public).to_bytes()
    }

    /// Check if two DH public keys are equal (constant-time)
    pub fn public_keys_equal(a: &PublicKey, b: &PublicKey) -> bool {
        constant_time_eq(a.as_bytes(), b.as_bytes())
    }

    /// Prune expired skipped message keys
    pub fn prune_expired_keys(keys: &mut HashMap<(PublicKey, u64), SkippedMessageKey>) {
        keys.retain(|_, v| !v.is_expired());
    }

    /// Get the number of non-expired skipped keys
    pub fn count_valid_skipped_keys(keys: &HashMap<(PublicKey, u64), SkippedMessageKey>) -> usize {
        keys.values().filter(|k| !k.is_expired()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_header_roundtrip() {
        let header = RatchetHeader {
            dh_public: [0x42u8; 32],
            message_number: 123,
            previous_chain_length: 456,
            timestamp: 789,
        };

        let bytes = header.to_bytes();
        let parsed = RatchetHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.dh_public, parsed.dh_public);
        assert_eq!(header.message_number, parsed.message_number);
        assert_eq!(header.previous_chain_length, parsed.previous_chain_length);
        assert_eq!(header.timestamp, parsed.timestamp);
    }

    #[test]
    fn test_ratchet_header_validation() {
        // Valid header
        let header = RatchetHeader {
            dh_public: [0x42u8; 32],
            message_number: 100,
            previous_chain_length: 50,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        assert!(header.validate().is_ok());

        // Invalid DH public key (all zeros)
        let header = RatchetHeader {
            dh_public: [0u8; 32],
            message_number: 100,
            previous_chain_length: 50,
            timestamp: 0,
        };
        assert!(header.validate().is_err());

        // Invalid message number
        let header = RatchetHeader {
            dh_public: [0x42u8; 32],
            message_number: 2_000_000_000_000,
            previous_chain_length: 50,
            timestamp: 0,
        };
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_skipped_message_key() {
        let key = [0x42u8; 32];
        let skipped = SkippedMessageKey::new(key, 100);

        assert_eq!(skipped.message_number, 100);
        assert!(!skipped.is_expired());
    }

    #[test]
    fn test_ratchet_message_roundtrip() {
        let header = RatchetHeader {
            dh_public: [0x42u8; 32],
            message_number: 100,
            previous_chain_length: 50,
            timestamp: 0,
        };

        let message = RatchetMessage {
            header,
            ciphertext: vec![0u8; 32],
        };

        let bytes = message.to_bytes();
        let parsed = RatchetMessage::from_bytes(&bytes).unwrap();

        assert_eq!(message.ciphertext, parsed.ciphertext);
    }

    #[test]
    fn test_generate_keypair() {
        let (secret, public) = utils::generate_keypair();
        let public_bytes = public.as_bytes();

        // Public key should not be all zeros
        assert!(!public_bytes.iter().all(|&b| b == 0));

        // DH agreement should work
        let (secret2, public2) = utils::generate_keypair();
        let shared1 = utils::dh_agree(&secret, &public2);
        let shared2 = utils::dh_agree(&secret2, &public);

        assert_eq!(shared1, shared2);
    }
}
