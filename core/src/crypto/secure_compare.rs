//! Constant-Time Comparison Operations
//!
//! Provides constant-time comparison functions to prevent timing attacks.
//! Re-implemented using the `subtle` crate for world-class protection.

use subtle::{ConstantTimeEq, Choice, ConditionallySelectable};

/// Compare two byte slices in constant time
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Compare two 32-byte arrays in constant time
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Compare two 64-byte arrays in constant time
pub fn constant_time_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time selection
pub fn constant_time_select(condition: bool, a: u8, b: u8) -> u8 {
    let mut val = b;
    val.conditional_assign(&a, Choice::from(condition as u8));
    val
}

/// Constant-time copy
pub fn constant_time_copy(condition: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    let choice = Choice::from(condition as u8);
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        d.conditional_assign(s, choice);
    }
}

/// Lexicographic byte-slice comparison for **non-sensitive** ordering only.
///
/// # ⚠️ SECURITY WARNING — NOT CONSTANT-TIME
/// Despite being in the `secure_compare` module, this function uses early-exit
/// comparisons and is **NOT** safe against timing attacks. It must never be
/// used to compare secrets, tokens, MACs, or any security-sensitive data.
/// Use `constant_time_eq` for any sensitive comparison.
#[doc(hidden)]
pub fn lexicographic_cmp_non_constant_time(a: &[u8], b: &[u8]) -> i8 {
    if a.len() != b.len() {
        return (a.len() as i8) - (b.len() as i8);
    }

    let mut result: i8 = 0;
    for i in 0..a.len() {
        let diff = (a[i] as i8) - (b[i] as i8);
        // Manual logic kept here for lexicographic non-sensitive ordering
        let is_equal = (result == 0) as i8;
        result = result * (1 - is_equal) + diff * is_equal;
    }

    result
}

/// Check if a byte slice is all zeros in constant time
pub fn constant_time_is_zero(slice: &[u8]) -> bool {
    slice.ct_eq(&vec![0u8; slice.len()]).into()
}

/// Check if a byte slice contains a specific byte in constant time
pub fn constant_time_contains(slice: &[u8], target: u8) -> bool {
    let mut found = Choice::from(0);
    for &byte in slice {
        found |= byte.ct_eq(&target);
    }
    found.into()
}

/// Constant-time memory comparison
pub fn constant_time_memcmp(a: &[u8], b: &[u8]) -> i32 {
    if a.len() != b.len() {
        return -1;
    }
    if a.ct_eq(b).into() {
        0
    } else {
        1
    }
}

/// Securely clear memory (Zeroize)
pub fn secure_zero(memory: &mut [u8]) {
    use zeroize::Zeroize;
    memory.zeroize();
}

/// Verify HMAC in constant time
pub fn verify_hmac(key: &[u8], data: &[u8], mac: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac_impl = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };

    mac_impl.update(data);
    let result = mac_impl.finalize();
    let computed_mac = result.into_bytes();

    computed_mac.ct_eq(mac).into()
}

/// Constant-time byte comparison, intended for comparing a password against
/// another byte sequence of equal length in constant time.
///
/// # ⚠️ WARNING — This is NOT a password verifier
/// This function compares raw bytes. It does NOT perform password hashing.
/// Never compare a plaintext password against a stored hash using this function —
/// that would expose the hash to timing attacks.
///
/// For correct password verification, use Argon2 or bcrypt:
///   - Hash the password with Argon2 at registration time
///   - Use `argon2::verify_encoded()` at login time (it is already constant-time)
///
/// This function is safe only for comparing two values that are already
/// derived through a KDF (e.g. two HMAC outputs of equal length).
pub fn secure_password_compare(password: &[u8], hash: &[u8]) -> bool {
    password.ct_eq(hash).into()
}

/// Batch constant-time comparison
pub fn batch_constant_time_compare(value: &[u8], candidates: &[&[u8]]) -> Option<usize> {
    let mut match_index = u32::MAX;
    let mut found_match = Choice::from(0);

    for (i, candidate) in candidates.iter().enumerate() {
        let is_match = value.ct_eq(candidate);
        let should_update = (!found_match) & is_match;
        match_index.conditional_assign(&(i as u32), should_update);
        found_match |= is_match;
    }

    if found_match.into() {
        Some(match_index as usize)
    } else {
        None
    }
}

/// Compare two 16-byte arrays
pub fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.ct_eq(b).into()
}

/// Compare two 48-byte arrays
pub fn constant_time_eq_48(a: &[u8; 48], b: &[u8; 48]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3];
        let b = [1, 2, 3];
        let c = [1, 2, 4];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_batch_compare() {
        let val = b"secret";
        let candidates: &[&[u8]] = &[b"wrong", b"secret", b"other"];
        assert_eq!(batch_constant_time_compare(val, candidates), Some(1));
        
        let val2 = b"missing";
        assert_eq!(batch_constant_time_compare(val2, candidates), None);
    }
}
