//! Safety Numbers and Identity Verification - Hardened Edition
//!
//! Implements safety number calculation for identity verification.
//! Safety numbers allow users to verify each other's identity keys
//! through an out-of-band channel (QR code, voice, etc.).

use sha2::{Sha256, Sha512, Digest};
use std::fmt;
use crate::crypto::constant_time_eq;
use crate::error::{ProtocolError, ProtocolResult};

/// Safety Number - A human-readable fingerprint for identity verification
///
/// The safety number is derived from both parties' identity keys and
/// provides a way to detect MITM attacks during initial key exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    /// The 60-digit safety number (displayed in groups of 5)
    digits: String,
    /// The raw 32-byte fingerprint
    fingerprint: [u8; 32],
    /// Version byte
    version: u8,
}

impl SafetyNumber {
    /// Current version
    pub const VERSION: u8 = 1;

    /// Calculate safety number from two identity keys
    ///
    /// # Arguments
    /// * `our_identity` - Our X25519 public key (32 bytes)
    /// * `their_identity` - Their X25519 public key (32 bytes)
    ///
    /// # Returns
    /// A SafetyNumber that can be displayed to users
    ///
    /// # Security
    /// - Uses SHA-512 for fingerprinting
    /// - Sorts keys lexicographically for consistent ordering
    /// - Includes version byte for future compatibility
    pub fn calculate(our_identity: &[u8; 32], their_identity: &[u8; 32]) -> Self {
        // Sort keys lexicographically for consistent ordering
        let (first, second) = if our_identity < their_identity {
            (our_identity, their_identity)
        } else {
            (their_identity, our_identity)
        };

        // Hash both keys together with version
        let mut hasher = Sha512::new();
        hasher.update(&[Self::VERSION]);
        hasher.update(b"SIBNA_SAFETY_NUMBER_V1");
        hasher.update(first);
        hasher.update(second);
        let result = hasher.finalize();

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&result[..32]);

        // Convert to 60 decimal digits
        let digits = Self::bytes_to_digits(&fingerprint);

        Self {
            digits,
            fingerprint,
            version: Self::VERSION,
        }
    }

    /// Calculate safety number with additional data
    ///
    /// # Arguments
    /// * `our_identity` - Our X25519 public key
    /// * `their_identity` - Their X25519 public key
    /// * `extra_data` - Additional data to include in calculation
    pub fn calculate_with_extra(
        our_identity: &[u8; 32],
        their_identity: &[u8; 32],
        extra_data: &[u8],
    ) -> Self {
        let (first, second) = if our_identity < their_identity {
            (our_identity, their_identity)
        } else {
            (their_identity, our_identity)
        };

        let mut hasher = Sha512::new();
        hasher.update(&[Self::VERSION]);
        hasher.update(b"SIBNA_SAFETY_NUMBER_V1_EXTRA");
        hasher.update(first);
        hasher.update(second);
        hasher.update(extra_data);
        let result = hasher.finalize();

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&result[..32]);

        let digits = Self::bytes_to_digits(&fingerprint);

        Self {
            digits,
            fingerprint,
            version: Self::VERSION,
        }
    }

    /// Convert first 32 bytes to 80 decimal digits (16 chunks of 2 bytes)
    fn bytes_to_digits(bytes: &[u8; 32]) -> String {
        // Use a base-10 encoding for better readability
        // We'll use 5 digits per 2 bytes (16 bits -> 5 decimal digits)
        
        let mut digits = String::with_capacity(95); // 80 digits + 15 spaces
        
        for (i, chunk) in bytes.chunks(2).enumerate() {
            if i > 0 && i % 3 == 0 {
                digits.push(' ');
            }
            
            let value = if chunk.len() == 2 {
                ((chunk[0] as u32) << 8) | (chunk[1] as u32)
            } else {
                (chunk[0] as u32) << 8
            };
            
            // Format as 5 digits with leading zeros
            digits.push_str(&format!("{:05}", value % 100000));
        }
        
        digits
    }

    /// Get the safety number as a formatted string
    pub fn as_string(&self) -> &str {
        &self.digits
    }

    /// Get the raw fingerprint bytes
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Get QR code data (encoded version of the safety number)
    pub fn qr_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(35);
        data.push(self.version);
        data.extend_from_slice(b"SB1"); // Sibna v1 prefix
        data.extend_from_slice(&self.fingerprint);
        data
    }

    /// Parse safety number from string
    pub fn parse(s: &str) -> Option<Self> {
        let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        
        if digits.len() != 80 {
            return None;
        }

        // Reverse the digit-to-bytes conversion
        let mut fingerprint = [0u8; 32];
        
        for (i, chunk) in digits.as_bytes().chunks(5).enumerate() {
            if i >= 16 {
                break;
            }
            
            let chunk_str = std::str::from_utf8(chunk).ok()?;
            let value: u32 = chunk_str.parse().ok()?;
            
            fingerprint[i * 2] = ((value >> 8) & 0xFF) as u8;
            fingerprint[i * 2 + 1] = (value & 0xFF) as u8;
        }

        Some(Self {
            digits: Self::bytes_to_digits(&fingerprint),
            fingerprint,
            version: Self::VERSION,
        })
    }

    /// Verify if another safety number matches (constant-time)
    pub fn verify(&self, other: &SafetyNumber) -> bool {
        constant_time_eq(&self.fingerprint, &other.fingerprint)
    }

    /// Compare two safety numbers (for sorting, not security)
    pub fn compare(&self, other: &SafetyNumber) -> std::cmp::Ordering {
        self.fingerprint.cmp(&other.fingerprint)
    }

    /// Get the version
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Calculate similarity score with another safety number
    /// (for detecting typos during manual verification)
    pub fn similarity(&self, other: &SafetyNumber) -> f64 {
        let mut matches = 0;
        for (a, b) in self.digits.chars().filter(|c| c.is_ascii_digit())
            .zip(other.digits.chars().filter(|c| c.is_ascii_digit())) {
            if a == b {
                matches += 1;
            }
        }
        matches as f64 / 80.0
    }
}

impl fmt::Display for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.digits)
    }
}

impl fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafetyNumber({})", self.digits)
    }
}

/// QR Code data for identity verification
#[derive(Clone)]
pub struct VerificationQrCode {
    /// Version byte
    version: u8,
    /// Our identity key
    identity_key: [u8; 32],
    /// Our device ID
    device_id: [u8; 16],
    /// Safety number fingerprint
    safety_fingerprint: [u8; 32],
    /// Verification status
    verified: bool,
    /// MAC key for integrity
    mac_key: [u8; 32],
}

impl VerificationQrCode {
    /// Create a new verification QR code
    pub fn new(
        identity_key: [u8; 32],
        device_id: [u8; 16],
        safety_fingerprint: [u8; 32],
        mac_key: [u8; 32],
    ) -> Self {
        Self {
            version: 1,
            identity_key,
            device_id,
            safety_fingerprint,
            verified: false,
            mac_key,
        }
    }

    /// Mark as verified
    pub fn mark_verified(&mut self) {
        self.verified = true;
    }

    /// Check if verified
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Encode to bytes for QR code generation
    /// FIX: mac_key is NO LONGER included in the serialized payload.
    /// Including a secret MAC key in a QR code is a critical vulnerability -
    /// anyone reading the QR code can forge any QR code they want.
    /// The MAC is now computed but the key stays private to the struct.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Layout: version(1) + SIBNA(5) + verified(1) + identity_key(32) + device_id(16) + fingerprint(32) = 87 bytes
        // Then: MAC(32) = 119 bytes total (no key in payload)
        let mut data = Vec::with_capacity(119);
        data.push(self.version);
        data.extend_from_slice(b"SIBNA"); // Magic bytes
        data.push(if self.verified { 1 } else { 0 });
        data.extend_from_slice(&self.identity_key);
        data.extend_from_slice(&self.device_id);
        data.extend_from_slice(&self.safety_fingerprint);
        // FIX: mac_key is NOT serialized - it is a private secret
        let mac = Self::calculate_mac(&data, &self.mac_key);
        data.extend_from_slice(&mac);
        data
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8], mac_key: &[u8; 32]) -> ProtocolResult<Self> {
        // FIX: New layout is 87 (header+keys) + 32 (MAC) = 119 bytes (no key in payload)
        if data.len() != 119 {
            return Err(ProtocolError::InvalidMessage);
        }

        let version = data[0];
        if version != 1 {
            return Err(ProtocolError::VersionMismatch);
        }

        // Verify magic bytes
        if &data[1..6] != b"SIBNA" {
            return Err(ProtocolError::InvalidMessage);
        }

        let verified = data[6] != 0;

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&data[7..39]);

        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&data[39..55]);

        let mut safety_fingerprint = [0u8; 32];
        safety_fingerprint.copy_from_slice(&data[55..87]);

        // Verify MAC (will fail with zero key unless bypassed intentionally)
        let mac = &data[87..119];
        let expected_mac = Self::calculate_mac(&data[..87], mac_key);
        if !constant_time_eq(mac, &expected_mac) {
            return Err(ProtocolError::AuthenticationFailed);
        }

        Ok(Self {
            version,
            identity_key,
            device_id,
            safety_fingerprint,
            verified,
            mac_key: *mac_key,
        })
    }

    /// Calculate MAC for integrity
    fn calculate_mac(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            // HMAC accepts any key size; [u8;32] is always valid
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key size"));
        mac.update(data);
        let result = mac.finalize();
        result.into_bytes().into()
    }

    /// Get the identity key
    pub fn identity_key(&self) -> &[u8; 32] {
        &self.identity_key
    }

    /// Get the device ID
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// Get the safety fingerprint
    pub fn safety_fingerprint(&self) -> &[u8; 32] {
        &self.safety_fingerprint
    }
}

/// Safety number comparison result
#[derive(Clone, Copy, Debug)]
pub enum ComparisonResult {
    /// Numbers match exactly
    Match,
    /// Numbers are similar (possible typo)
    Similar(f64),
    /// Numbers don't match
    Mismatch,
}

impl PartialEq for ComparisonResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Match, Self::Match) => true,
            (Self::Mismatch, Self::Mismatch) => true,
            (Self::Similar(a), Self::Similar(b)) => (a - b).abs() < f64::EPSILON,
            _ => false,
        }
    }
}

impl Eq for ComparisonResult {}

/// Compare two safety numbers
pub fn compare_safety_numbers(a: &SafetyNumber, b: &SafetyNumber) -> ComparisonResult {
    if a.verify(b) {
        ComparisonResult::Match
    } else {
        let similarity = a.similarity(b);
        if similarity > 0.8 {
            ComparisonResult::Similar(similarity)
        } else {
            ComparisonResult::Mismatch
        }
    }
}

/// Generate a safety number from prekey bundles
pub fn safety_number_from_bundles(
    our_bundle: &crate::handshake::PreKeyBundle,
    their_bundle: &crate::handshake::PreKeyBundle,
) -> SafetyNumber {
    SafetyNumber::calculate(
        &our_bundle.identity_key,
        &their_bundle.identity_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_number_calculation() {
        let key1 = [0x42u8; 32];
        let key2 = [0x24u8; 32];

        let sn1 = SafetyNumber::calculate(&key1, &key2);
        let sn2 = SafetyNumber::calculate(&key2, &key1);

        // Order shouldn't matter
        assert!(sn1.verify(&sn2));
    }

    #[test]
    fn test_safety_number_format() {
        let key1 = [0x42u8; 32];
        let key2 = [0x24u8; 32];

        let sn = SafetyNumber::calculate(&key1, &key2);
        let display = sn.as_string();

        // Should have spaces
        assert!(display.contains(' '));
        
        // Should only contain digits and spaces
        for c in display.chars() {
            assert!(c.is_ascii_digit() || c == ' ');
        }

        // Should have 80 digits
        let digits_only: String = display.chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits_only.len(), 80);
    }

    #[test]
    fn test_safety_number_parse() {
        let key1 = [0x42u8; 32];
        let key2 = [0x24u8; 32];

        let sn = SafetyNumber::calculate(&key1, &key2);
        let parsed = SafetyNumber::parse(sn.as_string()).unwrap();

        assert!(sn.verify(&parsed));
    }

    #[test]
    fn test_qr_code_roundtrip() {
        let identity_key = [0x42u8; 32];
        let device_id = [0x01u8; 16];
        let fingerprint = [0xABu8; 32];

        let mac_key = [0x99u8; 32];
        let qr = VerificationQrCode::new(identity_key, device_id, fingerprint, mac_key);
        let bytes = qr.to_bytes();
        
        let parsed = VerificationQrCode::from_bytes(&bytes, &mac_key).unwrap();
        
        assert_eq!(qr.identity_key, parsed.identity_key);
        assert_eq!(qr.device_id, parsed.device_id);
    }

    #[test]
    fn test_qr_code_tamper_detection() {
        let identity_key = [0x42u8; 32];
        let device_id = [0x01u8; 16];
        let fingerprint = [0xABu8; 32];

        let mac_key = [0x99u8; 32];
        let qr = VerificationQrCode::new(identity_key, device_id, fingerprint, mac_key);
        let mut bytes = qr.to_bytes();
        
        // Tamper with the data
        bytes[10] ^= 0xFF;
        
        assert!(VerificationQrCode::from_bytes(&bytes, &mac_key).is_err());
    }

    #[test]
    fn test_safety_number_similarity() {
        let key1 = [0x42u8; 32];
        let key2 = [0x24u8; 32];
        let key3 = [0x43u8; 32];

        let sn1 = SafetyNumber::calculate(&key1, &key2);
        let sn2 = SafetyNumber::calculate(&key1, &key2);
        let sn3 = SafetyNumber::calculate(&key1, &key3);

        // Same keys should have similarity 1.0
        assert_eq!(sn1.similarity(&sn2), 1.0);

        // Different keys should have low similarity
        assert!(sn1.similarity(&sn3) < 0.5);
    }

    #[test]
    fn test_comparison_result() {
        let key1 = [0x42u8; 32];
        let key2 = [0x24u8; 32];

        let sn1 = SafetyNumber::calculate(&key1, &key2);
        let sn2 = SafetyNumber::calculate(&key1, &key2);
        let sn3 = SafetyNumber::calculate(&key2, &key1);

        assert_eq!(compare_safety_numbers(&sn1, &sn2), ComparisonResult::Match);
        assert_eq!(compare_safety_numbers(&sn1, &sn3), ComparisonResult::Match);
    }

    #[test]
    fn test_safety_number_with_extra_data() {
        let key1 = [0x42u8; 32];
        let key2 = [0x24u8; 32];

        let sn1 = SafetyNumber::calculate(&key1, &key2);
        let sn2 = SafetyNumber::calculate_with_extra(&key1, &key2, b"extra");

        // Should be different
        assert!(!sn1.verify(&sn2));
    }
}
