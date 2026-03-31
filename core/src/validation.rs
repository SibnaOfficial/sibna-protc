#![allow(missing_docs)]
//! Input Validation and Sanitization - Hardened Edition
//!
//! Comprehensive input validation for all external-facing APIs.
//! Prevents injection attacks, buffer overflows, and malformed data.

use crate::error::ProtocolError;
use crate::crypto::{constant_time_eq, constant_time_is_zero};

/// Maximum sizes for various inputs
pub mod limits {
    /// Maximum message size (10 MB)
    pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
    /// Minimum message size
    pub const MIN_MESSAGE_SIZE: usize = 1;
    /// Maximum session ID length
    pub const MAX_SESSION_ID_LEN: usize = 256;
    /// Minimum session ID length
    pub const MIN_SESSION_ID_LEN: usize = 1;
    /// Maximum group ID length
    pub const MAX_GROUP_ID_LEN: usize = 64;
    /// Minimum group ID length
    pub const MIN_GROUP_ID_LEN: usize = 1;
    /// Maximum associated data length - aligned with crypto layer limit (256 bytes)
    /// FIX: Was 1024, but CryptoHandler::encrypt enforces MAX_INFO_LENGTH=256.
    /// Using >256 bytes of AD would silently fail at crypto layer.
    pub const MAX_AD_LEN: usize = 256;
    /// Maximum key size
    pub const MAX_KEY_SIZE: usize = 32;
    /// Minimum key size
    pub const MIN_KEY_SIZE: usize = 16;
    /// Maximum signature size (Ed25519)
    pub const MAX_SIGNATURE_SIZE: usize = 64;
    /// Maximum password length
    pub const MAX_PASSWORD_LEN: usize = 256;
    /// Minimum password length
    pub const MIN_PASSWORD_LEN: usize = 8;
    /// Maximum metadata size
    pub const MAX_METADATA_SIZE: usize = 4096;
    /// Maximum identity key length
    pub const MAX_IDENTITY_KEY_LEN: usize = 32;
    /// Maximum prekey bundle size
    pub const MAX_PREKEY_BUNDLE_SIZE: usize = 1024;
    /// Maximum device ID length
    pub const MAX_DEVICE_ID_LEN: usize = 32;
    /// Maximum group size
    pub const MAX_GROUP_SIZE: usize = 1000;
    /// Maximum message number
    pub const MAX_MESSAGE_NUMBER: u64 = 1_000_000_000_000;
    /// Maximum ciphertext size
    pub const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE + 1024;
    /// Minimum ciphertext size (nonce + tag + 1 byte)
    pub const MIN_CIPHERTEXT_SIZE: usize = 12 + 16 + 1;
    /// Maximum username length
    pub const MAX_USERNAME_LEN: usize = 64;
    /// Maximum user ID length
    pub const MAX_USER_ID_LEN: usize = 64;
    /// Maximum timestamp age (5 minutes)
    pub const MAX_TIMESTAMP_AGE_SECS: u64 = 300;
    /// Maximum timestamp in future (30 seconds)
    pub const MAX_TIMESTAMP_FUTURE_SECS: u64 = 30;
}

/// Validation error types
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// Input is too short
    TooShort { min: usize, actual: usize },
    /// Input is too long
    TooLong { max: usize, actual: usize },
    /// Input has invalid length
    InvalidLength { expected: usize, actual: usize },
    /// Input contains invalid bytes
    InvalidBytes { reason: String },
    /// Input is empty
    Empty,
    /// Input contains null bytes
    NullByte,
    /// Input failed cryptographic validation
    CryptoValidation { reason: String },
    /// Input contains invalid characters
    InvalidCharacters,
    /// Input format is invalid
    InvalidFormat,
    /// Input is outside valid range
    OutOfRange,
    /// Input is expired
    Expired,
    /// Input is from the future
    FutureTimestamp,
    /// Input is a duplicate
    Duplicate,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(f, "Input too short: expected at least {} bytes, got {}", min, actual)
            }
            Self::TooLong { max, actual } => {
                write!(f, "Input too long: expected at most {} bytes, got {}", max, actual)
            }
            Self::InvalidLength { expected, actual } => {
                write!(f, "Invalid length: expected {} bytes, got {}", expected, actual)
            }
            Self::InvalidBytes { reason } => {
                write!(f, "Invalid bytes: {}", reason)
            }
            Self::Empty => write!(f, "Input is empty"),
            Self::NullByte => write!(f, "Input contains null byte"),
            Self::CryptoValidation { reason } => {
                write!(f, "Cryptographic validation failed: {}", reason)
            }
            Self::InvalidCharacters => write!(f, "Input contains invalid characters"),
            Self::InvalidFormat => write!(f, "Input format is invalid"),
            Self::OutOfRange => write!(f, "Input is outside valid range"),
            Self::Expired => write!(f, "Input has expired"),
            Self::FutureTimestamp => write!(f, "Input timestamp is in the future"),
            Self::Duplicate => write!(f, "Input is a duplicate"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validation result type
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validate a message (plaintext or ciphertext)
pub fn validate_message(data: &[u8]) -> ValidationResult<()> {
    if data.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if data.len() > limits::MAX_MESSAGE_SIZE {
        return Err(ValidationError::TooLong {
            max: limits::MAX_MESSAGE_SIZE,
            actual: data.len(),
        });
    }

    if data.len() < limits::MIN_MESSAGE_SIZE {
        return Err(ValidationError::TooShort {
            min: limits::MIN_MESSAGE_SIZE,
            actual: data.len(),
        });
    }
    
    Ok(())
}

/// Validate a ciphertext
pub fn validate_ciphertext(data: &[u8]) -> ValidationResult<()> {
    if data.is_empty() {
        return Err(ValidationError::Empty);
    }

    if data.len() < limits::MIN_CIPHERTEXT_SIZE {
        return Err(ValidationError::TooShort {
            min: limits::MIN_CIPHERTEXT_SIZE,
            actual: data.len(),
        });
    }
    
    if data.len() > limits::MAX_CIPHERTEXT_SIZE {
        return Err(ValidationError::TooLong {
            max: limits::MAX_CIPHERTEXT_SIZE,
            actual: data.len(),
        });
    }

    Ok(())
}

/// Validate a session ID
pub fn validate_session_id(id: &[u8]) -> ValidationResult<()> {
    if id.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if id.len() > limits::MAX_SESSION_ID_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_SESSION_ID_LEN,
            actual: id.len(),
        });
    }

    if id.len() < limits::MIN_SESSION_ID_LEN {
        return Err(ValidationError::TooShort {
            min: limits::MIN_SESSION_ID_LEN,
            actual: id.len(),
        });
    }
    
    // Check for null bytes
    if id.contains(&0) {
        return Err(ValidationError::NullByte);
    }

    // Check for control characters
    if id.iter().any(|&b| b < 32) {
        return Err(ValidationError::InvalidCharacters);
    }
    
    Ok(())
}

/// Validate a key (should be exactly 32 bytes)
pub fn validate_key(key: &[u8]) -> ValidationResult<()> {
    if key.len() != limits::MAX_KEY_SIZE {
        return Err(ValidationError::InvalidLength {
            expected: limits::MAX_KEY_SIZE,
            actual: key.len(),
        });
    }
    
    // Check that key is not all zeros (weak key)
    if constant_time_is_zero(key) {
        return Err(ValidationError::InvalidBytes {
            reason: "Key is all zeros (weak key)".to_string(),
        });
    }

    // Check for repeating patterns (simple check)
    let half = key.len() / 2;
    if constant_time_eq(&key[..half], &key[half..]) {
        return Err(ValidationError::InvalidBytes {
            reason: "Key has repeating pattern (weak key)".to_string(),
        });
    }
    
    Ok(())
}

/// Validate a signature (should be exactly 64 bytes for Ed25519)
pub fn validate_signature(sig: &[u8]) -> ValidationResult<()> {
    if sig.len() != limits::MAX_SIGNATURE_SIZE {
        return Err(ValidationError::InvalidLength {
            expected: limits::MAX_SIGNATURE_SIZE,
            actual: sig.len(),
        });
    }

    // Check for all zeros (invalid signature)
    if constant_time_is_zero(sig) {
        return Err(ValidationError::InvalidBytes {
            reason: "Signature is all zeros".to_string(),
        });
    }
    
    Ok(())
}

/// Validate associated data
pub fn validate_associated_data(ad: &[u8]) -> ValidationResult<()> {
    if ad.len() > limits::MAX_AD_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_AD_LEN,
            actual: ad.len(),
        });
    }
    
    Ok(())
}

/// Validate a password
pub fn validate_password(password: &[u8]) -> ValidationResult<()> {
    if password.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if password.len() < limits::MIN_PASSWORD_LEN {
        return Err(ValidationError::TooShort {
            min: limits::MIN_PASSWORD_LEN,
            actual: password.len(),
        });
    }
    
    if password.len() > limits::MAX_PASSWORD_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_PASSWORD_LEN,
            actual: password.len(),
        });
    }
    
    // Check for null bytes
    if password.contains(&0) {
        return Err(ValidationError::NullByte);
    }

    // Check password strength (at least one uppercase, one lowercase, one digit)
    let has_upper = password.iter().any(|&b| b.is_ascii_uppercase());
    let has_lower = password.iter().any(|&b| b.is_ascii_lowercase());
    let has_digit = password.iter().any(|&b| b.is_ascii_digit());

    if !has_upper || !has_lower || !has_digit {
        return Err(ValidationError::InvalidBytes {
            reason: "Password must contain uppercase, lowercase, and digit".to_string(),
        });
    }
    
    Ok(())
}

/// Validate a group ID
pub fn validate_group_id(id: &[u8]) -> ValidationResult<()> {
    if id.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if id.len() > limits::MAX_GROUP_ID_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_GROUP_ID_LEN,
            actual: id.len(),
        });
    }

    if id.len() < limits::MIN_GROUP_ID_LEN {
        return Err(ValidationError::TooShort {
            min: limits::MIN_GROUP_ID_LEN,
            actual: id.len(),
        });
    }
    
    Ok(())
}

/// Validate message number (prevent overflow)
pub fn validate_message_number(n: u64) -> ValidationResult<()> {
    if n > limits::MAX_MESSAGE_NUMBER {
        return Err(ValidationError::OutOfRange);
    }
    
    Ok(())
}

/// Validate metadata
pub fn validate_metadata(metadata: &[u8]) -> ValidationResult<()> {
    if metadata.len() > limits::MAX_METADATA_SIZE {
        return Err(ValidationError::TooLong {
            max: limits::MAX_METADATA_SIZE,
            actual: metadata.len(),
        });
    }
    
    Ok(())
}

/// Validate a prekey bundle
pub fn validate_prekey_bundle(
    identity_key: &[u8],
    signed_prekey: &[u8],
    signature: &[u8],
    onetime_prekey: Option<&[u8]>,
) -> ValidationResult<()> {
    // Validate identity key
    validate_key(identity_key)?;

    // Validate signed prekey
    validate_key(signed_prekey)?;

    // Validate signature
    validate_signature(signature)?;
    
    // Validate onetime prekey if present
    if let Some(opk) = onetime_prekey {
        validate_key(opk)?;
    }

    // Check that keys are not identical (potential attack)
    if constant_time_eq(identity_key, signed_prekey) {
        return Err(ValidationError::InvalidBytes {
            reason: "Identity key and signed prekey must be different".to_string(),
        });
    }
    
    Ok(())
}

/// Validate handshake output
pub fn validate_handshake_output(
    shared_secret: &[u8],
    ephemeral_key: &[u8],
) -> ValidationResult<()> {
    // Shared secret should be 32 bytes
    if shared_secret.len() != limits::MAX_KEY_SIZE {
        return Err(ValidationError::InvalidLength {
            expected: limits::MAX_KEY_SIZE,
            actual: shared_secret.len(),
        });
    }
    
    // Ephemeral key should be 32 bytes
    if ephemeral_key.len() != limits::MAX_KEY_SIZE {
        return Err(ValidationError::InvalidLength {
            expected: limits::MAX_KEY_SIZE,
            actual: ephemeral_key.len(),
        });
    }
    
    // Check shared secret is not all zeros (possible DH failure)
    if constant_time_is_zero(shared_secret) {
        return Err(ValidationError::CryptoValidation {
            reason: "Shared secret is all zeros - possible DH failure".to_string(),
        });
    }

    // Check ephemeral key is not all zeros
    if constant_time_is_zero(ephemeral_key) {
        return Err(ValidationError::InvalidBytes {
            reason: "Ephemeral key is all zeros".to_string(),
        });
    }
    
    Ok(())
}

/// Validate a timestamp
pub fn validate_timestamp(timestamp: u64) -> ValidationResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ValidationError::InvalidFormat)?
        .as_secs();

    // Check for future timestamp
    if timestamp > now + limits::MAX_TIMESTAMP_FUTURE_SECS {
        return Err(ValidationError::FutureTimestamp);
    }

    // Check for expired timestamp
    if now > timestamp + limits::MAX_TIMESTAMP_AGE_SECS {
        return Err(ValidationError::Expired);
    }

    Ok(())
}

/// Validate a username
pub fn validate_username(username: &str) -> ValidationResult<()> {
    if username.is_empty() {
        return Err(ValidationError::Empty);
    }

    if username.len() > limits::MAX_USERNAME_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_USERNAME_LEN,
            actual: username.len(),
        });
    }

    // Check for valid characters (alphanumeric, underscore, hyphen)
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(ValidationError::InvalidCharacters);
    }

    // Must start with letter
    if !username.chars().next().map_or(false, |c| c.is_ascii_alphabetic()) {
        return Err(ValidationError::InvalidFormat);
    }

    Ok(())
}

/// Validate a device ID
pub fn validate_device_id(device_id: &[u8]) -> ValidationResult<()> {
    if device_id.is_empty() {
        return Err(ValidationError::Empty);
    }

    if device_id.len() > limits::MAX_DEVICE_ID_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_DEVICE_ID_LEN,
            actual: device_id.len(),
        });
    }

    Ok(())
}

/// Sanitize a string input (remove control characters)
pub fn sanitize_string(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Sanitize a byte array (remove null bytes)
pub fn sanitize_bytes(data: &[u8]) -> Vec<u8> {
    data.iter()
        .filter(|&&b| b != 0)
        .copied()
        .collect()
}

/// Check if data contains only printable ASCII
pub fn is_printable_ascii(data: &[u8]) -> bool {
    data.iter().all(|&b| b.is_ascii_graphic() || b == b' ')
}

/// Convert ValidationError to ProtocolError
impl From<ValidationError> for ProtocolError {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::Empty => ProtocolError::InvalidArgument,
            ValidationError::TooShort { .. } => ProtocolError::InvalidArgument,
            ValidationError::TooLong { .. } => ProtocolError::InvalidArgument,
            ValidationError::InvalidLength { .. } => ProtocolError::InvalidKeyLength,
            ValidationError::InvalidBytes { .. } => ProtocolError::InvalidMessage,
            ValidationError::NullByte => ProtocolError::InvalidArgument,
            ValidationError::CryptoValidation { .. } => ProtocolError::AuthenticationFailed,
            ValidationError::InvalidCharacters => ProtocolError::InvalidArgument,
            ValidationError::InvalidFormat => ProtocolError::InvalidMessage,
            ValidationError::OutOfRange => ProtocolError::InvalidArgument,
            ValidationError::Expired => ProtocolError::MessageTooOld,
            ValidationError::FutureTimestamp => ProtocolError::MessageFromFuture,
            ValidationError::Duplicate => ProtocolError::ReplayAttackDetected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_key() {
        // Valid key (non-repeating)
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        assert!(validate_key(&key).is_ok());
        
        // Wrong length
        assert!(validate_key(&[1u8; 16]).is_err());
        
        // All zeros (weak)
        assert!(validate_key(&[0u8; 32]).is_err());

        // Repeating pattern
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&[1u8; 16]);
        key[16..].copy_from_slice(&[1u8; 16]);
        assert!(validate_key(&key).is_err());
    }

    #[test]
    fn test_validate_message() {
        // Valid message
        assert!(validate_message(b"hello").is_ok());
        
        // Empty
        assert!(validate_message(b"").is_err());
        
        // Too large
        let large = vec![0u8; limits::MAX_MESSAGE_SIZE + 1];
        assert!(validate_message(&large).is_err());
    }

    #[test]
    fn test_validate_password() {
        // Valid password
        assert!(validate_password(b"Password123").is_ok());
        
        // Too short
        assert!(validate_password(b"short").is_err());
        
        // Contains null
        assert!(validate_password(b"pass\x00word").is_err());

        // No uppercase
        assert!(validate_password(b"password123").is_err());

        // No digit
        assert!(validate_password(b"Password").is_err());
    }

    #[test]
    fn test_validate_ciphertext() {
        // Too short
        assert!(validate_ciphertext(&[0u8; 20]).is_err());
        
        // Valid (minimum)
        assert!(validate_ciphertext(&[0u8; 29]).is_ok());
    }

    #[test]
    fn test_validate_timestamp() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Valid timestamp
        assert!(validate_timestamp(now).is_ok());

        // Future timestamp (within tolerance)
        assert!(validate_timestamp(now + 10).is_ok());

        // Too far in future
        assert!(validate_timestamp(now + 100).is_err());

        // Too old
        assert!(validate_timestamp(now - 400).is_err());
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user-name").is_ok());

        // Empty
        assert!(validate_username("").is_err());

        // Invalid characters
        assert!(validate_username("user@name").is_err());

        // Starts with number
        assert!(validate_username("123user").is_err());
    }

    #[test]
    fn test_sanitize_string() {
        assert_eq!(sanitize_string("hello"), "hello");
        assert_eq!(sanitize_string("hello\x00world"), "helloworld");
        assert_eq!(sanitize_string("hello\nworld"), "hello\nworld");
    }

    #[test]
    fn test_validate_prekey_bundle() {
        let ik = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let spk = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ];
        let sig = [0x55u8; 64];

        assert!(validate_prekey_bundle(&ik, &spk, &sig, None).is_ok());

        // Same keys (invalid)
        assert!(validate_prekey_bundle(&ik, &ik, &sig, None).is_err());
    }
}
