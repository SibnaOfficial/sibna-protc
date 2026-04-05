#![allow(missing_docs)]
//! Secure Random Number Generation

use super::{CryptoError, CryptoResult};
use rand_core::{CryptoRng, RngCore};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

const ENTROPY_POOL_SIZE: usize = 64;

#[derive(Clone)]
pub struct SecureRandom {
    rng: OsRng,
    entropy_pool: [u8; ENTROPY_POOL_SIZE],
    bytes_generated: u64,
    max_bytes_before_reseed: u64,
}

impl SecureRandom {
    pub fn new() -> CryptoResult<Self> {
        let mut rng = OsRng;
        let mut entropy_pool = [0u8; ENTROPY_POOL_SIZE];

        rng.fill_bytes(&mut entropy_pool);

        // Mix in environmental noise (v1.2)
        let pid = std::process::id().to_le_bytes();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes();
        
        for (i, &b) in pid.iter().chain(now.iter()).enumerate() {
            entropy_pool[i % ENTROPY_POOL_SIZE] ^= b;
        }

        if entropy_pool.iter().all(|&b| b == 0) {
            return Err(CryptoError::RandomFailed);
        }

        // MEMORY PINNING (Audit v2.0): Pin the entropy pool to RAM to prevent 
        // it being swapped to disk where it could be recovered by an attacker.
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Memory::VirtualLock;
            let _ = VirtualLock(entropy_pool.as_ptr() as *const _, ENTROPY_POOL_SIZE);
        }
        #[cfg(unix)]
        unsafe {
            let _ = libc::mlock(entropy_pool.as_ptr() as *const _, ENTROPY_POOL_SIZE);
        }

        Ok(Self {
            rng,
            entropy_pool,
            bytes_generated: 0,
            max_bytes_before_reseed: 1_000_000,
        })
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        if self.bytes_generated.saturating_add(buf.len() as u64)
            > self.max_bytes_before_reseed
        {
            self.reseed();
        }

        self.rng.fill_bytes(buf);

        for (i, byte) in buf.iter_mut().enumerate() {
            *byte ^= self.entropy_pool[i % ENTROPY_POOL_SIZE];
        }

        self.update_entropy_pool(buf);

        self.bytes_generated =
            self.bytes_generated.saturating_add(buf.len() as u64);
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    pub fn gen_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }

        let mask = max.next_power_of_two() - 1;

        loop {
            let val = self.next_u64() & mask;
            if val < max {
                return val;
            }
        }
    }

    pub fn gen_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.fill_bytes(&mut buf);
        buf
    }

    fn reseed(&mut self) {
        self.rng.fill_bytes(&mut self.entropy_pool);
        self.bytes_generated = 0;
    }

    fn update_entropy_pool(&mut self, generated: &[u8]) {
        for (i, &byte) in generated.iter().enumerate() {
            let idx = i % ENTROPY_POOL_SIZE;
            self.entropy_pool[idx] =
                self.entropy_pool[idx].wrapping_add(byte).rotate_left(3);
        }
    }

    pub fn bytes_generated(&self) -> u64 {
        self.bytes_generated
    }

    pub fn needs_reseed(&self) -> bool {
        self.bytes_generated >= self.max_bytes_before_reseed
    }
}

impl Zeroize for SecureRandom {
    fn zeroize(&mut self) {
        self.entropy_pool.zeroize();
        self.bytes_generated = 0;
    }
}

impl ZeroizeOnDrop for SecureRandom {}

impl Drop for SecureRandom {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Memory::VirtualUnlock;
            let _ = VirtualUnlock(self.entropy_pool.as_ptr() as *const _, ENTROPY_POOL_SIZE);
        }
        #[cfg(unix)]
        unsafe {
            let _ = libc::munlock(self.entropy_pool.as_ptr() as *const _, ENTROPY_POOL_SIZE);
        }
    }
}

impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        SecureRandom::next_u32(self)
    }

    fn next_u64(&mut self) -> u64 {
        SecureRandom::next_u64(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        SecureRandom::fill_bytes(self, dest)
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SecureRandom {}

thread_local! {
    static THREAD_RNG: std::cell::RefCell<Option<SecureRandom>> =
        std::cell::RefCell::new(None);
}

fn with_thread_rng<F, R>(f: F) -> CryptoResult<R>
where
    F: FnOnce(&mut SecureRandom) -> R,
{
    THREAD_RNG.with(|cell| {
        let mut borrow = cell.borrow_mut();

        if borrow.is_none() {
            *borrow = Some(SecureRandom::new()?);
        }

        borrow
            .as_mut()
            .ok_or(CryptoError::RandomFailed)
            .map(f)
    })
}

// =========================
// FIXED PUBLIC API
// =========================

pub fn random_bytes(buf: &mut [u8]) {
    let _ = with_thread_rng(|rng| rng.fill_bytes(buf));
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    random_bytes(&mut buf);
    buf
}

pub fn random_u64() -> u64 {
    with_thread_rng(|rng| rng.next_u64())
        .expect("ENTROPY_CRITICAL: RNG initialization failed")
}

pub fn shuffle<T>(slice: &mut [T]) {
    let len = slice.len();
    if len <= 1 {
        return;
    }

    let _ = with_thread_rng(|rng| {
        for i in (1..len).rev() {
            let j = rng.gen_range((i + 1) as u64) as usize;
            slice.swap(i, j);
        }
    });
}

pub fn random_alphanumeric(len: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    with_thread_rng(|rng| {
        (0..len)
            .map(|_| {
                CHARSET[rng.gen_range(CHARSET.len() as u64) as usize]
                    as char
            })
            .collect()
    })
    .expect("ENTROPY_CRITICAL: RNG initialization failed")
}

// =========================
// ENTROPY CHECK
// =========================

pub fn check_entropy() -> CryptoResult<()> {
    let mut buf = [0u8; 32];
    random_bytes(&mut buf);

    if buf.iter().all(|&b| b == 0) {
        return Err(CryptoError::InsufficientEntropy);
    }

    let unique: std::collections::HashSet<u8> =
        buf.iter().copied().collect();

    if unique.len() < 8 {
        return Err(CryptoError::InsufficientEntropy);
    }

    Ok(())
}

// =========================
// TESTS
// =========================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_creation() {
        assert!(SecureRandom::new().is_ok());
    }

    #[test]
    fn test_fill_bytes() {
        let mut rng = SecureRandom::new().unwrap();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        assert!(!buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_uniqueness() {
        let mut rng = SecureRandom::new().unwrap();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng.fill_bytes(&mut buf1);
        rng.fill_bytes(&mut buf2);
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_check_entropy() {
        assert!(check_entropy().is_ok());
    }
}
