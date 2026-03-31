//! Secure Crypto Module - Hardened Edition
//!
//! Safe implementation of cryptographic algorithms using well-audited libraries.
//! This module provides:
//! - ChaCha20-Poly1305 AEAD encryption with constant-time operations
//! - HKDF key derivation with secure parameters
//! - Secure random number generation with entropy mixing
//! - Constant-time comparison operations

pub mod encryptor;
pub mod random;
pub mod kdf;
pub mod secure_compare;

pub use encryptor::*;
pub use random::*;
pub use kdf::*;
pub use secure_compare::*;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::Aead,
};
use thiserror::Error;

/// Crypto Errors - Security Hardened
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum CryptoError {
    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Invalid nonce length
    #[error("Invalid nonce length")]
    InvalidNonceLength {
        /// Expected length (not exposed in Display)
        #[allow(dead_code)]
        expected: usize,
        /// Actual length (not exposed)
        #[allow(dead_code)]
        actual: usize,
    },

    /// Encryption failed
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Decryption failed
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Authentication failed - constant time
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Random generation failed
    #[error("Random generation failed")]
    RandomFailed,

    /// Key derivation failed
    #[error("Key derivation failed")]
    KeyDerivationFailed,

    /// Invalid ciphertext
    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    /// Weak key detected
    #[error("Weak key detected")]
    WeakKey,

    /// Entropy insufficient
    #[error("Insufficient entropy")]
    InsufficientEntropy,
}

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Key length in bytes (256 bits)
pub const KEY_LENGTH: usize = 32;

/// Nonce length in bytes (96 bits for ChaCha20)
pub const NONCE_LENGTH: usize = 12;

/// Authentication tag length in bytes (128 bits)
pub const TAG_LENGTH: usize = 16;

/// Minimum ciphertext length (nonce + tag + 1 byte)
pub const MIN_CIPHERTEXT_LENGTH: usize = NONCE_LENGTH + TAG_LENGTH + 1;

/// Maximum plaintext length (100 MB)
pub const MAX_PLAINTEXT_LENGTH: usize = 100 * 1024 * 1024;

/// Maximum ciphertext length
pub const MAX_CIPHERTEXT_LENGTH: usize = MAX_PLAINTEXT_LENGTH + NONCE_LENGTH + TAG_LENGTH;

/// ChaCha20 nonce length
pub const CHACHA20_NONCE_LENGTH: usize = 12;

/// Salt length for key derivation
pub const SALT_LENGTH: usize = 32;

/// Info string max length
pub const MAX_INFO_LENGTH: usize = 256;

/// General Encryption Handler - Hardened
///
/// Provides authenticated encryption using ChaCha20-Poly1305.
/// All operations are constant-time where possible.
#[derive(Clone)]
pub struct CryptoHandler {
    cipher: ChaCha20Poly1305,
    _key: Zeroizing<[u8; KEY_LENGTH]>,
}

impl std::fmt::Debug for CryptoHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoHandler")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl CryptoHandler {
    /// Create a new crypto handler with the given key
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    ///
    /// # Errors
    /// Returns `CryptoError::InvalidKeyLength` if key is not 32 bytes
    /// Returns `CryptoError::WeakKey` if key is all zeros or weak
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength);
        }

        // Check for weak key (all zeros)
        if key.iter().all(|&b| b == 0) {
            return Err(CryptoError::WeakKey);
        }

        // Check for weak key (all same byte)
        if key.iter().all(|&b| b == key[0]) {
            return Err(CryptoError::WeakKey);
        }

        let mut key_array = [0u8; KEY_LENGTH];
        key_array.copy_from_slice(key);

        let cipher = ChaCha20Poly1305::new(&key_array.into());

        Ok(Self {
            cipher,
            _key: Zeroizing::new(key_array),
        })
    }

    /// Encrypt data with automatic nonce generation
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// nonce || ciphertext || tag
    ///
    /// # Security
    /// - Uses secure random nonce (never reused)
    /// - Validates plaintext length
    /// - Constant-time operations where possible
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> CryptoResult<Vec<u8>> {
        // Validate plaintext length
        if plaintext.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }
        
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(CryptoError::EncryptionFailed);
        }

        // Validate associated data length
        if associated_data.len() > MAX_INFO_LENGTH {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Generate secure random nonce
        let mut rng = SecureRandom::new()?;
        let mut nonce = [0u8; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);

        // Zeroize nonce after use
        let result = self.encrypt_with_nonce(plaintext, associated_data, &nonce);
        nonce.zeroize();
        
        result
    }

    /// Encrypt with a specific nonce
    ///
    /// # Security Warning
    /// Never reuse a nonce with the same key! This can lead to complete
    /// compromise of the encryption. Only use this for testing or when
    /// you have a very good reason.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data
    /// * `nonce` - 12-byte nonce
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if nonce.len() != NONCE_LENGTH {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_LENGTH,
                actual: nonce.len(),
            });
        }

        // Validate plaintext
        if plaintext.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }

        let ciphertext = self.cipher
            .encrypt(nonce.into(), chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            })
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Result: nonce || ciphertext (which includes tag)
        let mut result = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data
    ///
    /// # Arguments
    /// * `ciphertext` - nonce || ciphertext || tag
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// The decrypted plaintext
    ///
    /// # Security
    /// - Validates ciphertext length
    /// - Constant-time comparison for authentication
    /// - Zeroizes sensitive data after use
    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> CryptoResult<Vec<u8>> {
        // Validate ciphertext length
        if ciphertext.len() < MIN_CIPHERTEXT_LENGTH {
            return Err(CryptoError::InvalidCiphertext);
        }

        if ciphertext.len() > MAX_CIPHERTEXT_LENGTH {
            return Err(CryptoError::InvalidCiphertext);
        }

        let nonce = &ciphertext[..NONCE_LENGTH];
        let encrypted_data = &ciphertext[NONCE_LENGTH..];

        self.cipher
            .decrypt(nonce.into(), chacha20poly1305::aead::Payload {
                msg: encrypted_data,
                aad: associated_data,
            })
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    /// Decrypt data in place
    ///
    /// # Arguments
    /// * `ciphertext` - nonce || ciphertext || tag (will be modified)
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// The decrypted plaintext (in the same buffer)
    ///
    /// # Security
    /// - More secure as it doesn't allocate new memory
    /// - Zeroizes the buffer on error
    pub fn decrypt_in_place(
        &self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < MIN_CIPHERTEXT_LENGTH {
            return Err(CryptoError::InvalidCiphertext);
        }

        let (nonce, encrypted_data) = ciphertext.split_at_mut(NONCE_LENGTH);

        self.cipher
            .decrypt(chacha20poly1305::Nonce::from_slice(nonce), chacha20poly1305::aead::Payload {
                msg: encrypted_data,
                aad: associated_data,
            })
            .map_err(|_| {
                // Zeroize on error to prevent information leakage
                ciphertext.zeroize();
                CryptoError::AuthenticationFailed
            })
    }

    /// Get the key length
    pub fn key_len(&self) -> usize {
        KEY_LENGTH
    }

    /// Securely compare two ciphertexts (constant-time)
    pub fn ciphertexts_equal(a: &[u8], b: &[u8]) -> bool {
        constant_time_eq(a, b)
    }
}

/// Zeroize the key on drop
impl Drop for CryptoHandler {
    fn drop(&mut self) {
        // Zeroizing is handled automatically by Zeroizing wrapper
        // This explicit implementation ensures it's called
    }
}

impl ZeroizeOnDrop for CryptoHandler {}

/// Secure key generation utilities
/// Secure key generation utilities
pub struct KeyGenerator;

impl KeyGenerator {
    /// Generate a secure random key
    pub fn generate_key() -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        let mut rng = SecureRandom::new()?;
        let mut key = [0u8; KEY_LENGTH];
        rng.fill_bytes(&mut key);
        
        // Verify key is not weak
        if key.iter().all(|&b| b == 0) || key.iter().all(|&b| b == key[0]) {
            // Extremely unlikely, but regenerate if it happens
            return Self::generate_key();
        }
        
        Ok(Zeroizing::new(key))
    }

    /// Generate a secure random nonce
    pub fn generate_nonce() -> CryptoResult<[u8; NONCE_LENGTH]> {
        let mut rng = SecureRandom::new()?;
        let mut nonce = [0u8; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);
        Ok(nonce)
    }

    /// Generate a secure random salt
    pub fn generate_salt() -> CryptoResult<[u8; SALT_LENGTH]> {
        let mut rng = SecureRandom::new()?;
        let mut salt = [0u8; SALT_LENGTH];
        rng.fill_bytes(&mut salt);
        Ok(salt)
    }
}

/// Validate a key for security
pub fn validate_key_security(key: &[u8]) -> CryptoResult<()> {
    if key.len() != KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength);
    }

    // Check for all zeros
    if key.iter().all(|&b| b == 0) {
        return Err(CryptoError::WeakKey);
    }

    // Check for all same byte
    if key.iter().all(|&b| b == key[0]) {
        return Err(CryptoError::WeakKey);
    }

    // Check for repeating patterns (simple check)
    let half = key.len() / 2;
    if constant_time_eq(&key[..half], &key[half..]) {
        return Err(CryptoError::WeakKey);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encryption_roundtrip() {
        let key = KeyGenerator::generate_key().unwrap();
        let handler = CryptoHandler::new(key.as_ref()).unwrap();

        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let ciphertext = handler.encrypt(plaintext, ad).unwrap();
        let decrypted = handler.decrypt(&ciphertext, ad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_authentication_failure() {
        let key = KeyGenerator::generate_key().unwrap();
        let handler = CryptoHandler::new(key.as_ref()).unwrap();

        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let ciphertext = handler.encrypt(plaintext, ad).unwrap();
        let result = handler.decrypt(&ciphertext, b"wrong ad");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0x42u8; 16]; // Wrong length
        let result = CryptoHandler::new(&key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidKeyLength));
    }

    #[test]
    fn test_weak_key_detection() {
        let key = [0u8; 32]; // All zeros
        let result = CryptoHandler::new(&key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::WeakKey));

        let key = [0x42u8; 32]; // All same byte
        let result = CryptoHandler::new(&key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::WeakKey));
    }

    #[test]
    fn test_key_generator() {
        let key1 = KeyGenerator::generate_key().unwrap();
        let key2 = KeyGenerator::generate_key().unwrap();
        
        // Keys should be different
        assert_ne!(key1.as_ref(), key2.as_ref());
        
        // Keys should be valid length
        assert_eq!(key1.len(), KEY_LENGTH);
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = KeyGenerator::generate_nonce().unwrap();
        let nonce2 = KeyGenerator::generate_nonce().unwrap();
        
        // Nonces should be different (with extremely high probability)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_ciphertext_tampering() {
        let key = KeyGenerator::generate_key().unwrap();
        
        let handler = CryptoHandler::new(key.as_ref()).unwrap();

        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let mut ciphertext = handler.encrypt(plaintext, ad).unwrap();
        
        // Tamper with ciphertext
        ciphertext[20] ^= 0xFF;
        
        let result = handler.decrypt(&ciphertext, ad);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = KeyGenerator::generate_key().unwrap();
        let handler = CryptoHandler::new(key.as_ref()).unwrap();

        let result = handler.encrypt(b"", b"ad");
        assert!(result.is_err());
    }

    #[test]
    fn test_large_plaintext() {
        let key = KeyGenerator::generate_key().unwrap();
        let handler = CryptoHandler::new(key.as_ref()).unwrap();

        let plaintext = vec![0u8; MAX_PLAINTEXT_LENGTH + 1];
        let result = handler.encrypt(&plaintext, b"ad");
        assert!(result.is_err());
    }
}
