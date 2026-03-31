//! Constant-Time Comparison Operations
//!
//! Provides constant-time comparison functions to prevent timing attacks.

// No imports needed for these functions as they are self-contained or use hmac/sha2 locally.

/// Compare two byte slices in constant time
///
/// # Security
/// This function performs a constant-time comparison to prevent timing attacks.
/// It always takes the same amount of time regardless of where the slices differ.
///
/// # Arguments
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
/// `true` if the slices are equal, `false` otherwise
///
/// # Example
/// ```
/// use sibna_core::crypto::constant_time_eq;
///
/// let a = [1, 2, 3, 4];
/// let b = [1, 2, 3, 4];
/// let c = [1, 2, 3, 5];
///
/// assert!(constant_time_eq(&a, &b));
/// assert!(!constant_time_eq(&a, &c));
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Compare two 32-byte arrays in constant time
///
/// This is optimized for comparing fixed-size keys
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result: u8 = 0;
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Compare two 64-byte arrays in constant time
pub fn constant_time_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    let mut result: u8 = 0;
    for i in 0..64 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Constant-time selection
///
/// Selects between two values based on a condition without branching
///
/// # Arguments
/// * `condition` - If true, returns a; if false, returns b
/// * `a` - Value to return if condition is true
/// * `b` - Value to return if condition is false
///
/// # Security
/// This function avoids branching to prevent timing attacks
pub fn constant_time_select(condition: bool, a: u8, b: u8) -> u8 {
    // Convert condition to mask (0xFF if true, 0x00 if false)
    let mask = -(condition as i8) as u8;
    (a & mask) | (b & !mask)
}

/// Constant-time copy
///
/// Copies `src` to `dst` if `condition` is true, otherwise leaves `dst` unchanged
///
/// # Security
/// This function avoids branching and always copies the same amount of data
pub fn constant_time_copy(condition: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());

    let mask = -(condition as i8) as u8;

    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Lexicographic byte-slice comparison.
///
/// # SECURITY WARNING
/// This function is NOT constant-time. Do NOT use for MAC or key comparison.
/// Use `constant_time_eq()` for all security-sensitive comparisons.
/// This function exists only for non-sensitive sorting/ordering operations.
#[doc(hidden)] // Hide from public API to discourage misuse
pub fn constant_time_cmp(a: &[u8], b: &[u8]) -> i8 {
    if a.len() != b.len() {
        // Return difference in lengths (not constant time, but lengths are public)
        return (a.len() as i8) - (b.len() as i8);
    }

    let mut result: i8 = 0;
    for i in 0..a.len() {
        let diff = (a[i] as i8) - (b[i] as i8);
        // Only update result if we haven't found a difference yet
        let is_equal = (result == 0) as i8;
        result = result * (1 - is_equal) + diff * is_equal;
    }

    result
}

/// Check if a byte slice is all zeros in constant time
///
/// # Security
/// This function always scans the entire slice
pub fn constant_time_is_zero(slice: &[u8]) -> bool {
    let mut result: u8 = 0;
    for &byte in slice {
        result |= byte;
    }
    result == 0
}

/// Check if a byte slice contains a specific byte in constant time
///
/// # Security
/// This function always scans the entire slice
pub fn constant_time_contains(slice: &[u8], target: u8) -> bool {
    let mut result: u8 = 0;
    for &byte in slice {
        result |= (byte ^ target).wrapping_sub(1) >> 7;
    }
    result != 0
}

/// Constant-time memory comparison (like memcmp but constant-time)
///
/// Returns 0 if equal, non-zero otherwise
pub fn constant_time_memcmp(a: &[u8], b: &[u8]) -> i32 {
    if a.len() != b.len() {
        return -1;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    // Convert to -1, 0, or 1
    if result == 0 {
        0
    } else {
        1
    }
}

/// Securely clear memory
///
/// This function ensures the compiler doesn't optimize away the zeroing
pub fn secure_zero(memory: &mut [u8]) {
    // Use volatile write to prevent optimization
    for byte in memory.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }

    // Memory barrier
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

/// Verify a MAC in constant time
///
/// # Arguments
/// * `expected` - Expected MAC value
/// * `actual` - Actual MAC value
///
/// # Returns
/// `true` if MACs are equal, `false` otherwise
///
/// # Security
/// This function uses constant-time comparison to prevent timing attacks
pub fn verify_mac(expected: &[u8], actual: &[u8]) -> bool {
    constant_time_eq(expected, actual)
}

/// Verify a MAC with additional data
///
/// This is useful for verifying MACs over data that includes a nonce or timestamp
pub fn verify_mac_with_data(mac: &[u8], data: &[u8], key: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac_impl = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };

    mac_impl.update(data);
    let result = mac_impl.finalize();
    let computed_mac = result.into_bytes();

    constant_time_eq(mac, &computed_mac)
}

/// Secure comparison for passwords
///
/// This function compares passwords in constant time and provides
/// additional protection against timing attacks
pub fn secure_password_compare(password: &[u8], hash: &[u8]) -> bool {
    // Use a minimum comparison time to prevent timing attacks
    let start = std::time::Instant::now();
    let result = constant_time_eq(password, hash);
    let elapsed = start.elapsed();

    // Minimum comparison time (100 microseconds)
    let min_time = std::time::Duration::from_micros(100);
    if elapsed < min_time {
        std::thread::sleep(min_time - elapsed);
    }

    result
}

/// Compare two 16-byte arrays (for UUIDs, etc.)
pub fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut result: u8 = 0;
    for i in 0..16 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Compare two 48-byte arrays
pub fn constant_time_eq_48(a: &[u8; 48], b: &[u8; 48]) -> bool {
    let mut result: u8 = 0;
    for i in 0..48 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Batch constant-time comparison
///
/// Compares a value against multiple candidates in constant time
/// and returns the index of the match (or None if no match)
pub fn batch_constant_time_compare(value: &[u8], candidates: &[&[u8]]) -> Option<usize> {
    let mut match_index: usize = usize::MAX;
    let mut found_match: u8 = 0;

    for (i, candidate) in candidates.iter().enumerate() {
        let is_match = constant_time_eq(value, candidate) as u8;
        // Only update if we haven't found a match yet
        let should_update = found_match ^ 1;
        match_index = match_index * (1 - should_update as usize) + i * should_update as usize;
        found_match |= is_match;
    }

    if found_match != 0 {
        Some(match_index)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        let d = [1, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn test_constant_time_eq_32() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x24u8; 32];

        assert!(constant_time_eq_32(&a, &b));
        assert!(!constant_time_eq_32(&a, &c));
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(true, 10, 20), 10);
        assert_eq!(constant_time_select(false, 10, 20), 20);
    }

    #[test]
    fn test_constant_time_copy() {
        let mut dst = [0u8; 4];
        let src = [1, 2, 3, 4];

        constant_time_copy(true, &mut dst, &src);
        assert_eq!(dst, src);

        let mut dst = [0u8; 4];
        constant_time_copy(false, &mut dst, &src);
        assert_eq!(dst, [0, 0, 0, 0]);
    }

    #[test]
    fn test_constant_time_is_zero() {
        assert!(constant_time_is_zero(&[0, 0, 0, 0]));
        assert!(!constant_time_is_zero(&[0, 0, 0, 1]));
        assert!(!constant_time_is_zero(&[1, 0, 0, 0]));
    }

    #[test]
    fn test_constant_time_contains() {
        assert!(constant_time_contains(&[1, 2, 3, 4], 3));
        assert!(!constant_time_contains(&[1, 2, 3, 4], 5));
    }

    #[test]
    fn test_constant_time_memcmp() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert_eq!(constant_time_memcmp(&a, &b), 0);
        assert_ne!(constant_time_memcmp(&a, &c), 0);
    }

    #[test]
    fn test_secure_zero() {
        let mut data = [1, 2, 3, 4, 5];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_verify_mac() {
        let mac1 = [1, 2, 3, 4];
        let mac2 = [1, 2, 3, 4];
        let mac3 = [1, 2, 3, 5];

        assert!(verify_mac(&mac1, &mac2));
        assert!(!verify_mac(&mac1, &mac3));
    }

    #[test]
    fn test_batch_compare() {
        let value = [1, 2, 3, 4];
        let candidates: &[&[u8]] = &[
            &[5, 6, 7, 8],
            &[1, 2, 3, 4],
            &[9, 10, 11, 12],
        ];

        assert_eq!(batch_constant_time_compare(&value, candidates), Some(1));

        let candidates: &[&[u8]] = &[
            &[5, 6, 7, 8],
            &[9, 10, 11, 12],
        ];

        assert_eq!(batch_constant_time_compare(&value, candidates), None);
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3];

        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_timing_resistance() {
        // This test verifies that constant_time_eq takes similar time
        // for equal and unequal inputs
        let a = vec![0u8; 1000];
        let b = vec![0u8; 1000];
        let c = vec![1u8; 1000];

        // Warm up
        for _ in 0..100 {
            let _ = constant_time_eq(&a, &b);
            let _ = constant_time_eq(&a, &c);
        }

        // Measure equal comparison
        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _ = constant_time_eq(&a, &b);
        }
        let equal_time = start.elapsed();

        // Measure unequal comparison
        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _ = constant_time_eq(&a, &c);
        }
        let unequal_time = start.elapsed();

        // Times should be similar (within 20%)
        let ratio = if equal_time > unequal_time {
            equal_time.as_nanos() as f64 / unequal_time.as_nanos() as f64
        } else {
            unequal_time.as_nanos() as f64 / equal_time.as_nanos() as f64
        };

        assert!(ratio < 1.2, "Timing difference too large: {:.2}", ratio);
    }
}
