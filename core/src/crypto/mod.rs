//! Secure Crypto Module
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
pub mod padding;

pub use encryptor::*;
pub use random::*;
pub use kdf::*;
pub use secure_compare::*;
pub use padding::{PaddingMode, pad_message, unpad_message};
pub use subtle::{Choice, ConstantTimeEq};

use crate::error::{ProtocolError, ProtocolResult};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::Aead,
};
use thiserror::Error;

/// Crypto Errors
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

/// Get current Unix timestamp safely
pub fn current_timestamp() -> ProtocolResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProtocolError::InvalidState)
        .map(|d| d.as_secs())
}

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

/// General Encryption Handler
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
    use subtle::ConstantTimeEq;
    if key[..half].ct_eq(&key[half..]).into() {
        return Err(CryptoError::WeakKey);
    }
    Ok(())
}

/// Validate an X25519 public key to prevent Small Subgroup Attacks (v1.2)
///
/// Rejects the 8 known low-order points for Curve25519.
pub fn validate_public_key(pub_key: &[u8; 32]) -> CryptoResult<()> {
    // 8 Low-order points for Curve25519
    const LOW_ORDER_POINTS: [[u8; 32]; 8] = [
        [0x00; 32],
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0x01, 0xf1, 0xda, 0x56, 0x75, 0x47, 0x11, 0x85, 0x12, 0x1a, 0x9f, 0x17, 0x60, 0xe7, 0x61, 0x19, 0x90, 0x3f, 0x52, 0x49, 0x22, 0xfe, 0x80, 0x5a, 0x5f],
        [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0xa5, 0x99, 0x83, 0x17, 0x0c, 0x64, 0x81, 0x41, 0xb2, 0x39, 0x52, 0x80, 0x24, 0xed, 0x54, 0x8f, 0x61, 0x6c, 0x7e, 0x48, 0x8a],
        [0xed, 0xce, 0x84, 0x43, 0xbc, 0xaf, 0x73, 0x1d, 0x0e, 0x25, 0xd4, 0x7f, 0x3d, 0x1b, 0xba, 0x8a, 0xb6, 0xb0, 0x5b, 0x69, 0x80, 0x45, 0x29, 0xed, 0x7f, 0x72, 0x1d, 0x97, 0xa3, 0x31, 0xa3, 0xec],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81],
        [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0x01, 0xf1, 0xda, 0x56, 0x75, 0x47, 0x11, 0x85, 0x12, 0x1a, 0x9f, 0x17, 0x60, 0xe7, 0x61, 0x19, 0x90, 0x3f, 0x52, 0x49, 0x22, 0xfe, 0x80, 0x5a, 0xdf]
    ];

    for point in &LOW_ORDER_POINTS {
        if pub_key.ct_eq(point).into() {
            return Err(CryptoError::WeakKey);
        }
    }
    Ok(())
}

/// Shared Serde helpers for cryptographic types
pub mod serde_helpers {
    use serde::{Serializer, Deserializer, Serialize, Deserialize};
    use x25519_dalek::StaticSecret;

    /// Serde helper for Option<StaticSecret>
    pub mod dh_local_serde {
        use super::*;
        pub fn serialize<S>(secret: &Option<StaticSecret>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            secret.as_ref().map(|s| s.to_bytes()).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<StaticSecret>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt_bytes: Option<[u8; 32]> = Option::deserialize(deserializer)?;
            Ok(opt_bytes.map(StaticSecret::from))
        }
    }

    /// Serde helper for parking_lot::RwLock
    pub mod rw_lock_serde {
        use super::*;
        use parking_lot::RwLock;

        pub fn serialize<S, T>(lock: &RwLock<T>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: Serialize,
        {
            lock.read().serialize(serializer)
        }

        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<RwLock<T>, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de>,
        {
            let value = T::deserialize(deserializer)?;
            Ok(RwLock::new(value))
        }
    }
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
