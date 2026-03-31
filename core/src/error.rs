//! Error types for the Sibna Protocol v9 - Production Hardened Edition
//!
//! This module defines all error types used throughout the protocol.
//! All errors are designed to prevent information leakage.

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol Error Type - Security Hardened
///
/// Comprehensive error enumeration for all protocol operations.
/// Errors are designed to prevent timing attacks and information leakage.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum ProtocolError {
    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Invalid key length with details (internal use only)
    #[error("Invalid key length")]
    InvalidKeyLengthDetailed {
        /// Expected length (not exposed in Display)
        #[allow(dead_code)]
        expected: usize,
        /// Actual length (not exposed in Display)
        #[allow(dead_code)]
        actual: usize,
    },

    /// Encryption failed
    #[error("Encryption operation failed")]
    EncryptionFailed,

    /// Encryption failed with internal details
    #[error("Encryption operation failed")]
    EncryptionFailedDetailed {
        /// Internal error details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Decryption failed
    #[error("Decryption operation failed")]
    DecryptionFailed,

    /// Decryption failed with internal details
    #[error("Decryption operation failed")]
    DecryptionFailedDetailed {
        /// Internal error details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Authentication failed - constant time comparison
    #[error("Authentication verification failed")]
    AuthenticationFailed,

    /// Invalid nonce
    #[error("Invalid nonce")]
    InvalidNonce,

    /// Invalid nonce length
    #[error("Invalid nonce")]
    InvalidNonceLength {
        /// Expected length (not exposed)
        #[allow(dead_code)]
        expected: usize,
        /// Actual length (not exposed)
        #[allow(dead_code)]
        actual: usize,
    },

    /// Session not found
    #[error("Session not found")]
    SessionNotFound,

    /// Invalid state
    #[error("Invalid protocol state")]
    InvalidState,

    /// Invalid state with internal details
    #[error("Invalid protocol state")]
    InvalidStateDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Key derivation failed
    #[error("Key derivation failed")]
    KeyDerivationFailed,

    /// Invalid message format
    #[error("Invalid message format")]
    InvalidMessage,

    /// Invalid message with internal details
    #[error("Invalid message format")]
    InvalidMessageDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Invalid signature
    #[error("Signature verification failed")]
    InvalidSignature,

    /// Handshake failed
    #[error("Handshake operation failed")]
    HandshakeFailed,

    /// Handshake failed with internal details
    #[error("Handshake operation failed")]
    HandshakeFailedDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Out of memory
    #[error("Memory allocation failed")]
    OutOfMemory,

    /// Internal error
    #[error("Internal error")]
    InternalError,

    /// Internal error with details (logged only)
    #[error("Internal error")]
    InternalErrorDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Invalid ciphertext
    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    /// Invalid key
    #[error("Invalid key")]
    InvalidKey,

    /// Random generation failed
    #[error("Random number generation failed")]
    RandomFailed,

    /// Key not found
    #[error("Key not found")]
    KeyNotFound,

    /// Invalid argument
    #[error("Invalid argument")]
    InvalidArgument,

    /// Invalid argument with details
    #[error("Invalid argument")]
    InvalidArgumentDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Storage error
    #[error("Storage operation failed")]
    StorageError,

    /// Storage error with details
    #[error("Storage operation failed")]
    StorageErrorDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Serialization error
    #[error("Data serialization failed")]
    SerializationError,

    /// Serialization error with details
    #[error("Data serialization failed")]
    SerializationErrorDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Deserialization error
    #[error("Data deserialization failed")]
    DeserializationError,

    /// Deserialization error with details
    #[error("Data deserialization failed")]
    DeserializationErrorDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Maximum skipped messages exceeded
    #[error("Message sequence limit exceeded")]
    MaxSkippedMessagesExceeded,

    /// Replay attack detected
    #[error("Message replay detected")]
    ReplayAttackDetected,

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Invalid password
    #[error("Invalid password")]
    InvalidPassword,

    /// Weak password
    #[error("Password does not meet security requirements")]
    WeakPassword,

    /// Compromised key detected
    #[error("Key compromise detected")]
    KeyCompromiseDetected,

    /// Protocol version mismatch
    #[error("Protocol version mismatch")]
    VersionMismatch,

    /// Device revoked
    #[error("Device has been revoked")]
    DeviceRevoked,

    /// Group operation failed
    #[error("Group operation failed")]
    GroupError,

    /// Group error with details
    #[error("Group operation failed")]
    GroupErrorDetailed {
        /// Internal details (not exposed)
        #[allow(dead_code)]
        details: String,
    },

    /// Verification failed
    #[error("Verification failed")]
    VerificationFailed,

    /// Tampering detected
    #[error("Data tampering detected")]
    TamperingDetected,

    /// Clock skew detected
    #[error("Clock synchronization issue detected")]
    ClockSkewDetected,

    /// Message too old
    #[error("Message is too old")]
    MessageTooOld,

    /// Message from future
    #[error("Message timestamp is in the future")]
    MessageFromFuture,

    /// Key or bundle has expired
    #[error("Key or bundle has expired")]
    Expired,
}

/// Result type for protocol operations
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Secure error wrapper that prevents information leakage
#[derive(Clone, Debug)]
pub struct SecureError {
    /// Public error message (safe to expose)
    pub public_message: &'static str,
    /// Internal error code for logging
    pub error_code: u32,
    /// Whether this error should be logged
    pub should_log: bool,
}

impl SecureError {
    /// Create a new secure error
    pub const fn new(public_message: &'static str, error_code: u32, should_log: bool) -> Self {
        Self {
            public_message,
            error_code,
            should_log,
        }
    }

    /// Get the public error message
    pub fn public_message(&self) -> &'static str {
        self.public_message
    }

    /// Get the error code
    pub fn error_code(&self) -> u32 {
        self.error_code
    }
}

// Predefined secure errors
impl SecureError {
    /// Generic encryption error
    pub const ENCRYPTION_FAILED: Self = Self::new("Encryption failed", 1001, true);
    /// Generic decryption error
    pub const DECRYPTION_FAILED: Self = Self::new("Decryption failed", 1002, true);
    /// Generic authentication error
    pub const AUTHENTICATION_FAILED: Self = Self::new("Authentication failed", 1003, true);
    /// Generic invalid input error
    pub const INVALID_INPUT: Self = Self::new("Invalid input", 1004, false);
    /// Generic internal error
    pub const INTERNAL_ERROR: Self = Self::new("Internal error", 1005, true);
}

/// Error context for detailed logging (internal use only)
#[derive(Clone, Debug)]
pub struct ErrorContext {
    /// File where error occurred
    pub file: &'static str,
    /// Line where error occurred
    pub line: u32,
    /// Function where error occurred
    pub function: &'static str,
    /// Additional context
    pub context: Option<String>,
}

impl ErrorContext {
    /// Create a new error context
    pub const fn new(file: &'static str, line: u32, function: &'static str) -> Self {
        Self {
            file,
            line,
            function,
            context: None,
        }
    }

    /// Add context to the error
    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }
}

/// Macro for creating errors with context
#[macro_export]
macro_rules! protocol_error {
    ($error_type:ident) => {
        $crate::error::ProtocolError::$error_type
    };
    ($error_type:ident, $details:expr) => {
        $crate::error::ProtocolError::{$error_type(stringify!($details).to_string())}
    };
}

/// Macro for creating errors with file and line information
#[macro_export]
macro_rules! protocol_err {
    ($error:expr) => {{
        #[cfg(debug_assertions)]
        {
            tracing::debug!(error = ?$error, file = file!(), line = line!(), "Protocol error occurred");
        }
        $error
    }};
}

impl From<crate::crypto::CryptoError> for ProtocolError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        match err {
            crate::crypto::CryptoError::InvalidKeyLength => ProtocolError::InvalidKeyLength,
            crate::crypto::CryptoError::EncryptionFailed => ProtocolError::EncryptionFailed,
            crate::crypto::CryptoError::DecryptionFailed => ProtocolError::DecryptionFailed,
            crate::crypto::CryptoError::AuthenticationFailed => ProtocolError::AuthenticationFailed,
            crate::crypto::CryptoError::InvalidNonceLength { expected, actual } => {
                ProtocolError::InvalidNonceLength { expected, actual }
            }
            crate::crypto::CryptoError::RandomFailed => ProtocolError::RandomFailed,
            crate::crypto::CryptoError::KeyDerivationFailed => ProtocolError::KeyDerivationFailed,
            crate::crypto::CryptoError::InvalidCiphertext => ProtocolError::InvalidCiphertext,
            crate::crypto::CryptoError::WeakKey => ProtocolError::InvalidKey,
            crate::crypto::CryptoError::InsufficientEntropy => ProtocolError::RandomFailed,
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(_err: std::io::Error) -> Self {
        // Don't expose internal IO error details
        ProtocolError::InternalError
    }
}

impl From<serde_json::Error> for ProtocolError {
    fn from(_err: serde_json::Error) -> Self {
        // Don't expose serialization error details
        ProtocolError::SerializationError
    }
}

impl From<std::array::TryFromSliceError> for ProtocolError {
    fn from(_err: std::array::TryFromSliceError) -> Self {
        ProtocolError::InvalidMessage
    }
}

impl From<std::num::TryFromIntError> for ProtocolError {
    fn from(_err: std::num::TryFromIntError) -> Self {
        ProtocolError::InvalidArgument
    }
}

impl From<std::str::Utf8Error> for ProtocolError {
    fn from(_err: std::str::Utf8Error) -> Self {
        ProtocolError::InvalidMessage
    }
}

impl From<std::string::FromUtf8Error> for ProtocolError {
    fn from(_err: std::string::FromUtf8Error) -> Self {
        ProtocolError::InvalidMessage
    }
}

impl Zeroize for ProtocolError {
    fn zeroize(&mut self) {
        // Clear any sensitive data in error variants
        match self {
            ProtocolError::InvalidKeyLengthDetailed { .. } => {
                *self = ProtocolError::InvalidKeyLength;
            }
            ProtocolError::EncryptionFailedDetailed { .. } => {
                *self = ProtocolError::EncryptionFailed;
            }
            ProtocolError::DecryptionFailedDetailed { .. } => {
                *self = ProtocolError::DecryptionFailed;
            }
            ProtocolError::InvalidStateDetailed { .. } => {
                *self = ProtocolError::InvalidState;
            }
            ProtocolError::InvalidMessageDetailed { .. } => {
                *self = ProtocolError::InvalidMessage;
            }
            ProtocolError::HandshakeFailedDetailed { .. } => {
                *self = ProtocolError::HandshakeFailed;
            }
            ProtocolError::InternalErrorDetailed { .. } => {
                *self = ProtocolError::InternalError;
            }
            ProtocolError::InvalidArgumentDetailed { .. } => {
                *self = ProtocolError::InvalidArgument;
            }
            ProtocolError::StorageErrorDetailed { .. } => {
                *self = ProtocolError::StorageError;
            }
            ProtocolError::SerializationErrorDetailed { .. } => {
                *self = ProtocolError::SerializationError;
            }
            ProtocolError::DeserializationErrorDetailed { .. } => {
                *self = ProtocolError::DeserializationError;
            }
            ProtocolError::GroupErrorDetailed { .. } => {
                *self = ProtocolError::GroupError;
            }
            _ => {}
        }
    }
}

impl ZeroizeOnDrop for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ProtocolError::InvalidKeyLength;
        assert_eq!(err.to_string(), "Invalid key length");

        let err = ProtocolError::AuthenticationFailed;
        assert_eq!(err.to_string(), "Authentication verification failed");
    }

    #[test]
    fn test_error_zeroize() {
        let mut err = ProtocolError::InvalidKeyLengthDetailed {
            expected: 32,
            actual: 16,
        };
        err.zeroize();
        assert!(matches!(err, ProtocolError::InvalidKeyLength));
    }

    #[test]
    fn test_secure_error() {
        let err = SecureError::ENCRYPTION_FAILED;
        assert_eq!(err.public_message(), "Encryption failed");
        assert_eq!(err.error_code(), 1001);
        assert!(err.should_log);
    }
}
