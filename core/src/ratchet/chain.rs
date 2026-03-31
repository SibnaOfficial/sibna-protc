#![allow(missing_docs)]
//! Chain Key Implementation - Hardened Production v9
//! FIX: derive_key now returns CryptoResult to propagate HMAC errors properly.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use crate::crypto::CryptoResult;
use crate::crypto::CryptoError;

const MESSAGE_KEY_SEED: u8 = 0x01;
const CHAIN_KEY_SEED: u8 = 0x02;
const HEADER_KEY_SEED: u8 = 0x03;

#[derive(Serialize, Deserialize)]
pub struct ChainKey {
    pub key: [u8; 32],
    pub index: u64,
    pub created_at: u64,
    pub max_messages: u64,
}

#[allow(missing_docs)]
impl ChainKey {
    pub const DEFAULT_MAX_MESSAGES: u64 = 1000;

    pub fn new(key: [u8; 32]) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self { key, index: 0, created_at, max_messages: Self::DEFAULT_MAX_MESSAGES }
    }

    pub fn with_max_messages(key: [u8; 32], max_messages: u64) -> Self {
        let mut ck = Self::new(key);
        ck.max_messages = max_messages;
        ck
    }

    /// FIX: Returns CryptoResult instead of panicking with ? in non-Result fn.
    pub fn next_message_key(&mut self) -> Option<[u8; 32]> {
        if self.index >= self.max_messages { return None; }
        let message_key = self.derive_key(MESSAGE_KEY_SEED).ok()?;
        let next_key = self.derive_key(CHAIN_KEY_SEED).ok()?;
        self.key.zeroize();
        self.key = next_key;
        self.index += 1;
        Some(message_key)
    }

    pub fn derive_header_key(&self) -> Option<[u8; 32]> {
        self.derive_key(HEADER_KEY_SEED).ok()
    }

    /// FIX: Proper return type - HMAC::new_from_slice can fail for empty keys.
    fn derive_key(&self, seed: u8) -> CryptoResult<[u8; 32]> {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        hmac.update(&[seed]);
        let result = hmac.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result.into_bytes()[..32]);
        Ok(key)
    }

    pub fn index(&self) -> u64 { self.index }

    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.created_at)
    }

    pub fn needs_rotation(&self) -> bool {
        self.index >= self.max_messages || self.age_secs() > 86400
    }

    pub fn remaining_messages(&self) -> u64 {
        self.max_messages.saturating_sub(self.index)
    }

    pub fn clone_key(&self) -> [u8; 32] { self.key }
}

impl Clone for ChainKey {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            index: self.index,
            created_at: self.created_at,
            max_messages: self.max_messages,
        }
    }
}

impl Zeroize for ChainKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.index = 0;
    }
}

impl ZeroizeOnDrop for ChainKey {}

impl Drop for ChainKey {
    fn drop(&mut self) { self.zeroize(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_derivation() {
        let key = [0x42u8; 32];
        let mut chain = ChainKey::new(key);
        let mk1 = chain.next_message_key().unwrap();
        let mk2 = chain.next_message_key().unwrap();
        let mk3 = chain.next_message_key().unwrap();
        assert_ne!(mk1, mk2);
        assert_ne!(mk2, mk3);
        assert_eq!(chain.index(), 3);
    }

    #[test]
    fn test_chain_key_limit() {
        let key = [0x01u8; 32];
        let mut chain = ChainKey::with_max_messages(key, 3);
        assert!(chain.next_message_key().is_some());
        assert!(chain.next_message_key().is_some());
        assert!(chain.next_message_key().is_some());
        assert!(chain.next_message_key().is_none());
    }
}
