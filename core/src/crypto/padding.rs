//! Message Padding — Metadata Size Protection
//!
//! Pads plaintext to fixed block sizes **before** AEAD encryption.
//! This prevents an observer from estimating message length from ciphertext size.
//!
//! # How It Works
//!
//! ```text
//! plaintext → pad_message(pt, block) → AEAD encrypt → send
//! receive   → AEAD decrypt           → unpad_message → plaintext
//! ```
//!
//! # Padding Format
//!
//! ```text
//! [ plaintext | random bytes | 2-byte LE padding_len ]
//! ```
//!
//! - `padding_len` = number of random padding bytes appended (0–65535)
//! - Total padded length is always a multiple of `block_size`
//! - Random padding bytes prevent pattern analysis across messages
//!
//! # Block Sizes
//!
//! | Mode | Block Size | Use Case |
//! |---|---|---|
//! | `Small` | 256 B | IoT / constrained devices |
//! | `Standard` (default) | 1 KB | General messaging |
//! | `Large` | 4 KB | File transfers / high-privacy |
//! | `Maximum` | 16 KB | Maximum metadata protection |
//! | `Custom(n)` | n bytes | Advanced integrators |

use crate::crypto::random::SecureRandom;
use crate::error::{ProtocolError, ProtocolResult};

/// Block size used for padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PaddingMode {
    /// No padding applied. Ciphertext size reveals plaintext size.
    ///
    /// **Not recommended** for production use — enables size-based traffic analysis.
    None,
    /// Pad to 256-byte blocks. Suitable for IoT / constrained devices.
    Small,
    /// Pad to 1024-byte blocks. **Recommended default** for general messaging.
    Standard,
    /// Pad to 4096-byte blocks. Recommended for high-privacy applications.
    Large,
    /// Pad to 16384-byte blocks. Maximum metadata protection.
    Maximum,
    /// Custom block size (must be a power of 2, minimum 64 bytes).
    Custom(usize),
}

impl PaddingMode {
    /// Returns the block size in bytes for this mode.
    pub fn block_size(&self) -> usize {
        match self {
            PaddingMode::None => 1,
            PaddingMode::Small => 256,
            PaddingMode::Standard => 1024,
            PaddingMode::Large => 4096,
            PaddingMode::Maximum => 16384,
            PaddingMode::Custom(n) => *n,
        }
    }

    /// Returns `true` if padding is enabled.
    pub fn is_enabled(&self) -> bool {
        !matches!(self, PaddingMode::None)
    }
}

impl Default for PaddingMode {
    fn default() -> Self {
        PaddingMode::Standard
    }
}

/// Padding overhead in bytes: 2 bytes for the length field.
pub const PADDING_OVERHEAD: usize = 2;

/// Maximum padding that can be encoded in 2 bytes.
pub const MAX_PADDING_BYTES: usize = 65535;

/// Pad a plaintext message to the next multiple of `mode.block_size()`.
///
/// # Format
/// `[ plaintext | random_padding | 2-byte LE length ]`
///
/// # Errors
/// - `InvalidArgument` if the resulting padded size would exceed 100 MB
/// - `RandomFailed` if the CSPRNG fails
pub fn pad_message(plaintext: &[u8], mode: PaddingMode) -> ProtocolResult<Vec<u8>> {
    if !mode.is_enabled() {
        return Ok(plaintext.to_vec());
    }

    let block = mode.block_size();
    let total_without_pad = plaintext.len() + PADDING_OVERHEAD;

    // How many bytes needed to reach the next block boundary?
    let remainder = total_without_pad % block;
    let pad_len = if remainder == 0 { 0 } else { block - remainder };

    if pad_len > MAX_PADDING_BYTES {
        return Err(ProtocolError::InvalidArgument);
    }

    let total = total_without_pad + pad_len;
    if total > 100 * 1024 * 1024 {
        return Err(ProtocolError::InvalidArgument);
    }

    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(plaintext);

    // Fill padding with random bytes to prevent pattern analysis
    if pad_len > 0 {
        let mut rng = SecureRandom::new().map_err(|_| ProtocolError::InternalError)?;
        let mut rand_buf = vec![0u8; pad_len];
        rng.fill_bytes(&mut rand_buf);
        output.extend_from_slice(&rand_buf);
    }

    // Append 2-byte little-endian padding length
    output.push((pad_len & 0xFF) as u8);
    output.push((pad_len >> 8) as u8);

    debug_assert_eq!(output.len() % block, 0, "padded size must be multiple of block");

    Ok(output)
}

/// Remove padding from a decrypted message.
///
/// # Errors
/// - `InvalidMessage` if the buffer is too short or the length field is corrupt
pub fn unpad_message(padded: &[u8]) -> ProtocolResult<Vec<u8>> {
    if padded.len() < PADDING_OVERHEAD {
        return Err(ProtocolError::InvalidMessage);
    }

    // Read 2-byte LE padding length from end
    let lo = padded[padded.len() - 2] as usize;
    let hi = padded[padded.len() - 1] as usize;
    let pad_len = lo | (hi << 8);

    let total_overhead = pad_len + PADDING_OVERHEAD;
    if total_overhead > padded.len() {
        return Err(ProtocolError::InvalidMessage);
    }

    let plaintext_len = padded.len() - total_overhead;
    Ok(padded[..plaintext_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let msg = b"Hello, Sibna!";
        for mode in [PaddingMode::Small, PaddingMode::Standard, PaddingMode::Large] {
            let padded = pad_message(msg, mode).unwrap();
            // Padded size must be exact multiple of block
            assert_eq!(padded.len() % mode.block_size(), 0, "not aligned: {mode:?}");
            // Must recover original
            let recovered = unpad_message(&padded).unwrap();
            assert_eq!(recovered, msg, "roundtrip failed for {mode:?}");
        }
    }

    #[test]
    fn test_padding_hides_size() {
        // Two messages of different lengths should have the SAME padded size
        // when they fall within the same block bucket
        let short = b"Hi";
        let long  = b"Hello, this is a longer message!";
        let padded_short = pad_message(short, PaddingMode::Standard).unwrap();
        let padded_long  = pad_message(long,  PaddingMode::Standard).unwrap();
        // Both should be exactly 1024 bytes (both < 1022 bytes of plaintext)
        assert_eq!(padded_short.len(), 1024);
        assert_eq!(padded_long.len(),  1024);
    }

    #[test]
    fn test_no_padding_mode() {
        let msg = b"no padding here";
        let out = pad_message(msg, PaddingMode::None).unwrap();
        assert_eq!(out, msg);
        // unpad on a non-padded message would be called differently by application
    }

    #[test]
    fn test_custom_block_size() {
        let msg = b"custom";
        let padded = pad_message(msg, PaddingMode::Custom(512)).unwrap();
        assert_eq!(padded.len() % 512, 0);
        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn test_unpad_corrupt_length() {
        // Buffer shorter than overhead
        let bad = [0u8; 1];
        assert!(unpad_message(&bad).is_err());

        // Padding length claims more bytes than buffer contains
        let mut buf = vec![0u8; 10];
        buf[8] = 200; // lo byte of pad_len = 200
        buf[9] = 0;
        assert!(unpad_message(&buf).is_err());
    }

    #[test]
    fn test_large_message_padding() {
        // Message that needs two full 1KB blocks
        let msg = vec![0x42u8; 1500];
        let padded = pad_message(&msg, PaddingMode::Standard).unwrap();
        assert_eq!(padded.len(), 2048); // next 1 KB block boundary
        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, msg);
    }
}
