//! Advanced Encryptor with Message Authentication
//!
//! Provides high-level encryption with message numbers and replay protection.

use super::{CryptoError, CryptoResult, SecureRandom, KEY_LENGTH, NONCE_LENGTH};
use super::super::validation::{validate_message, validate_associated_data};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::Aead,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Message header size
const MESSAGE_HEADER_SIZE: usize = 8 + 8 + 8; // message_number + timestamp + padding

/// Maximum message age in seconds (24 hours - allows offline/delayed delivery)
/// Note: This Encryptor-level check is a secondary defense; Double Ratchet provides
/// forward secrecy. Tighten to 300 for high-security deployments.
const MAX_MESSAGE_AGE_SECS: u64 = 86400;

/// Clock skew tolerance in seconds (30 seconds)
const CLOCK_SKEW_TOLERANCE_SECS: u64 = 30;

/// Message encryptor with replay protection
pub struct Encryptor {
    /// The cipher instance
    cipher: ChaCha20Poly1305,
    /// Current message number
    message_number: u64,
    /// Key (zeroized on drop)
    _key: Zeroizing<[u8; KEY_LENGTH]>,
    /// Maximum message number seen (for replay detection)
    max_message_number: u64,
    /// Seen message numbers (for replay detection)
    seen_numbers: std::collections::HashSet<u64>,
    /// Maximum seen numbers to track
    max_seen_numbers: usize,
}

impl Encryptor {
    /// Create a new encryptor with a key and initial message number
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `initial_message_number` - Starting message number
    pub fn new(key: &[u8], initial_message_number: u64) -> CryptoResult<Self> {
        if key.len() != KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut key_array = [0u8; KEY_LENGTH];
        key_array.copy_from_slice(key);

        let cipher = ChaCha20Poly1305::new(&key_array.into());

        Ok(Self {
            cipher,
            message_number: initial_message_number,
            _key: Zeroizing::new(key_array),
            max_message_number: initial_message_number,
            seen_numbers: std::collections::HashSet::new(),
            max_seen_numbers: 1000,
        })
    }

    /// Encrypt a message with authentication
    ///
    /// # Format
    /// message_number (8) || timestamp (8) || nonce (12) || ciphertext || tag (16)
    ///
    /// # Arguments
    /// * `plaintext` - Message to encrypt
    /// * `associated_data` - Additional authenticated data
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Validate inputs
        validate_message(plaintext).map_err(|_| CryptoError::InvalidCiphertext)?;
        validate_associated_data(associated_data).map_err(|_| CryptoError::InvalidCiphertext)?;

        // Generate nonce
        let mut nonce = [0u8; NONCE_LENGTH];
        SecureRandom::new()?.fill_bytes(&mut nonce);

        // Build header
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CryptoError::EncryptionFailed)?
            .as_secs();

        let header = self.build_header(self.message_number, timestamp);

        // Build associated data
        let mut full_ad = Vec::with_capacity(associated_data.len() + header.len());
        full_ad.extend_from_slice(associated_data);
        full_ad.extend_from_slice(&header);

        // Encrypt
        let ciphertext = self.cipher
            .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &full_ad,
            })
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Build final message
        let mut result = Vec::with_capacity(header.len() + NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(&header);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        // Increment message number
        self.message_number = self.message_number.wrapping_add(1);

        // Zeroize sensitive data
        nonce.zeroize();

        Ok(result)
    }

    /// Decrypt a message with replay protection
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted message
    /// * `associated_data` - Additional authenticated data
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Validate minimum length
        if ciphertext.len() < MESSAGE_HEADER_SIZE + NONCE_LENGTH + 16 {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Parse header
        let message_number = u64::from_le_bytes(
            ciphertext[0..8].try_into().map_err(|_| CryptoError::InvalidCiphertext)?
        );
        let timestamp = u64::from_le_bytes(
            ciphertext[8..16].try_into().map_err(|_| CryptoError::InvalidCiphertext)?
        );
        let _padding = u64::from_le_bytes(
            ciphertext[16..24].try_into().map_err(|_| CryptoError::InvalidCiphertext)?
        );

        // Check timestamp (prevent replay of old messages)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CryptoError::EncryptionFailed)?
            .as_secs();

        // Check for clock skew
        if timestamp > now + CLOCK_SKEW_TOLERANCE_SECS {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Check message age
        if now > timestamp + MAX_MESSAGE_AGE_SECS {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Check for replay
        if message_number <= self.max_message_number {
            if self.seen_numbers.contains(&message_number) {
                return Err(CryptoError::AuthenticationFailed);
            }
        }

        // Extract nonce and ciphertext
        let nonce = &ciphertext[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + NONCE_LENGTH];
        let encrypted = &ciphertext[MESSAGE_HEADER_SIZE + NONCE_LENGTH..];

        // Build header for verification
        let header = self.build_header(message_number, timestamp);

        // Build associated data
        let mut full_ad = Vec::with_capacity(associated_data.len() + header.len());
        full_ad.extend_from_slice(associated_data);
        full_ad.extend_from_slice(&header);

        // Decrypt
        let plaintext = self.cipher
            .decrypt(chacha20poly1305::Nonce::from_slice(nonce), chacha20poly1305::aead::Payload {
                msg: encrypted,
                aad: &full_ad,
            })
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        // Update replay protection state
        self.update_seen_numbers(message_number);

        Ok(plaintext)
    }

    /// Build message header
    fn build_header(&self, message_number: u64, timestamp: u64) -> Vec<u8> {
        let mut header = Vec::with_capacity(MESSAGE_HEADER_SIZE);
        header.extend_from_slice(&message_number.to_le_bytes());
        header.extend_from_slice(&timestamp.to_le_bytes());
        // Add padding for future use
        header.extend_from_slice(&[0u8; 8]);
        header
    }

    /// Update seen message numbers
    fn update_seen_numbers(&mut self, message_number: u64) {
        if message_number > self.max_message_number {
            self.max_message_number = message_number;
        }

        self.seen_numbers.insert(message_number);

        // Prune old numbers if we have too many
        if self.seen_numbers.len() > self.max_seen_numbers {
            let min_to_keep = self.max_message_number.saturating_sub(self.max_seen_numbers as u64);
            self.seen_numbers.retain(|&n| n > min_to_keep);
        }
    }

    /// Get current message number
    pub fn message_number(&self) -> u64 {
        self.message_number
    }

    /// Set maximum seen numbers to track
    pub fn set_max_seen_numbers(&mut self, max: usize) {
        self.max_seen_numbers = max;
    }

    /// Check if a message number is potentially a replay
    pub fn is_potential_replay(&self, message_number: u64) -> bool {
        message_number <= self.max_message_number && self.seen_numbers.contains(&message_number)
    }
}

impl Drop for Encryptor {
    fn drop(&mut self) {
        self.seen_numbers.clear();
    }
}

impl ZeroizeOnDrop for Encryptor {}

/// Streaming encryptor for large messages
pub struct StreamingEncryptor {
    /// Chunk size (1MB)
    chunk_size: usize,
    /// Encryptor for each chunk
    encryptor: Encryptor,
    /// Chunk counter
    chunk_counter: u64,
}

impl StreamingEncryptor {
    /// Create a new streaming encryptor
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            chunk_size: 1024 * 1024, // 1MB chunks
            encryptor: Encryptor::new(key, 0)?,
            chunk_counter: 0,
        })
    }

    /// Encrypt a large message in chunks
    pub fn encrypt_stream(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let num_chunks = (data.len() + self.chunk_size - 1) / self.chunk_size;
        let mut result = Vec::new();

        // Write header
        result.extend_from_slice(&(num_chunks as u64).to_le_bytes());

        for i in 0..num_chunks {
            let start = i * self.chunk_size;
            let end = ((i + 1) * self.chunk_size).min(data.len());
            let chunk = &data[start..end];

            // Encrypt chunk with chunk index as associated data
            let encrypted = self.encryptor.encrypt_message(
                chunk,
                &self.chunk_counter.to_le_bytes(),
            )?;

            // Write chunk length
            result.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
            // Write encrypted chunk
            result.extend_from_slice(&encrypted);

            self.chunk_counter += 1;
        }

        Ok(result)
    }

    /// Decrypt a stream
    pub fn decrypt_stream(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        if data.len() < 8 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let num_chunks = u64::from_le_bytes(data[0..8].try_into().map_err(|_| CryptoError::InvalidCiphertext)?);
        let mut result = Vec::new();
        let mut offset = 8;

        for _ in 0..num_chunks {
            if offset + 4 > data.len() {
                return Err(CryptoError::InvalidCiphertext);
            }

            let chunk_len = u32::from_le_bytes(
                data[offset..offset + 4].try_into().map_err(|_| CryptoError::InvalidCiphertext)?
            ) as usize;
            offset += 4;

            if offset + chunk_len > data.len() {
                return Err(CryptoError::InvalidCiphertext);
            }

            let encrypted_chunk = &data[offset..offset + chunk_len];
            let chunk = self.encryptor.decrypt_message(
                encrypted_chunk,
                &self.chunk_counter.to_le_bytes(),
            )?;

            result.extend_from_slice(&chunk);
            offset += chunk_len;
            self.chunk_counter += 1;
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryptor_creation() {
        let key = [0x42u8; 32];
        let encryptor = Encryptor::new(&key, 0);
        assert!(encryptor.is_ok());
    }

    #[test]
    fn test_encryption_roundtrip() {
        let key = [0x42u8; 32];
        let mut encryptor = Encryptor::new(&key, 0).unwrap();

        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let ciphertext = encryptor.encrypt_message(plaintext, ad).unwrap();
        let decrypted = encryptor.decrypt_message(&ciphertext, ad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_message_number_increment() {
        let key = [0x42u8; 32];
        let mut encryptor = Encryptor::new(&key, 0).unwrap();

        assert_eq!(encryptor.message_number(), 0);

        encryptor.encrypt_message(b"test", b"ad").unwrap();
        assert_eq!(encryptor.message_number(), 1);

        encryptor.encrypt_message(b"test", b"ad").unwrap();
        assert_eq!(encryptor.message_number(), 2);
    }

    #[test]
    fn test_replay_detection() {
        let key = [0x42u8; 32];
        let mut encryptor = Encryptor::new(&key, 0).unwrap();

        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        // Encrypt message
        let ciphertext = encryptor.encrypt_message(plaintext, ad).unwrap();

        // Decrypt successfully
        let decrypted = encryptor.decrypt_message(&ciphertext, ad).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);

        // Try to decrypt again (replay)
        let result = encryptor.decrypt_message(&ciphertext, ad);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_associated_data() {
        let key = [0x42u8; 32];
        let mut encryptor = Encryptor::new(&key, 0).unwrap();

        let plaintext = b"Hello, World!";
        let ad = b"correct ad";

        let ciphertext = encryptor.encrypt_message(plaintext, ad).unwrap();
        let result = encryptor.decrypt_message(&ciphertext, b"wrong ad");

        assert!(result.is_err());
    }

    #[test]
    fn test_streaming_encryptor() {
        let key = [0x42u8; 32];
        let mut encryptor = StreamingEncryptor::new(&key).unwrap();

        let data = vec![0xABu8; 1024 * 1024 * 2]; // 2MB
        let encrypted = encryptor.encrypt_stream(&data).unwrap();

        let mut decryptor = StreamingEncryptor::new(&key).unwrap();
        let decrypted = decryptor.decrypt_stream(&encrypted).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0x42u8; 16]; // Wrong length
        let result = Encryptor::new(&key, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let mut encryptor = Encryptor::new(&key, 0).unwrap();

        let result = encryptor.encrypt_message(b"", b"ad");
        assert!(result.is_err());
    }
}
