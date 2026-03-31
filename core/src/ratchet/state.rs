#![allow(missing_docs)]
//! Double Ratchet State - Hardened Edition
//!
//! Manages the state for the Double Ratchet algorithm with secure serialization.

use super::ChainKey;
use x25519_dalek::{PublicKey, StaticSecret};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;

/// Double Ratchet State
///
/// Contains all state needed for the Double Ratchet algorithm.
/// This includes:
/// - Root key for DH ratchet
/// - Sending and receiving chain keys
/// - DH key pairs
/// - Skipped message keys for out-of-order handling
#[derive(Serialize, Deserialize)]
pub struct DoubleRatchetState {
    /// Root key for KDF chain
    pub root_key: [u8; 32],

    /// Sending chain key
    pub sending_chain: Option<ChainKey>,

    /// Receiving chain key
    pub receiving_chain: Option<ChainKey>,

    /// Local DH private key (X25519) - not serialized
    #[serde(skip)]
    pub dh_local: Option<StaticSecret>,

    /// Serialized local DH public key bytes
    #[serde(with = "serde_bytes")]
    pub dh_local_bytes: Vec<u8>,

    /// Remote DH public key - not serialized
    #[serde(skip)]
    pub dh_remote: Option<PublicKey>,

    /// Serialized remote DH public key bytes
    pub dh_remote_bytes: Option<Vec<u8>>,

    /// Skipped message keys for out-of-order messages
    /// Key: (public_key_bytes, message_number)
    /// Value: message_key
    #[serde(with = "skipped_keys_serde")]
    pub skipped_message_keys: HashMap<([u8; 32], u64), [u8; 32]>,

    /// Maximum number of skipped messages to store
    #[serde(skip)]
    pub max_skip: usize,

    /// Previous chain length for header
    pub previous_counter: u64,

    /// State creation timestamp
    pub created_at: u64,

    /// Last activity timestamp
    pub last_activity: u64,

    /// State version for migrations
    pub version: u32,
}

impl DoubleRatchetState {
    /// Current state version
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new empty state
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            root_key: [0u8; 32],
            sending_chain: None,
            receiving_chain: None,
            dh_local: None,
            dh_local_bytes: Vec::new(),
            dh_remote: None,
            dh_remote_bytes: None,
            skipped_message_keys: HashMap::new(),
            max_skip: 2000,
            previous_counter: 0,
            created_at: now,
            last_activity: now,
            version: Self::CURRENT_VERSION,
        }
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Get state age in seconds
    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now.saturating_sub(self.created_at)
    }

    /// Get time since last activity
    pub fn idle_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now.saturating_sub(self.last_activity)
    }

    /// Check if state has expired (inactive for 30 days)
    pub fn is_expired(&self) -> bool {
        self.idle_secs() > 30 * 86400 // 30 days
    }

    /// Get the number of skipped message keys
    pub fn skipped_keys_count(&self) -> usize {
        self.skipped_message_keys.len()
    }

    /// Check if skipped keys limit is reached
    pub fn skipped_keys_full(&self) -> bool {
        self.skipped_message_keys.len() >= self.max_skip
    }

    /// Add a skipped message key
    pub fn add_skipped_key(&mut self, pub_key: [u8; 32], msg_num: u64, key: [u8; 32]) -> bool {
        if self.skipped_keys_full() {
            return false;
        }

        self.skipped_message_keys.insert((pub_key, msg_num), key);
        true
    }

    /// Get a skipped message key
    pub fn get_skipped_key(&self, pub_key: &[u8; 32], msg_num: u64) -> Option<&[u8; 32]> {
        self.skipped_message_keys.get(&(*pub_key, msg_num))
    }

    /// Remove a skipped message key
    pub fn remove_skipped_key(&mut self, pub_key: &[u8; 32], msg_num: u64) -> Option<[u8; 32]> {
        self.skipped_message_keys.remove(&(*pub_key, msg_num))
    }

    /// Clear all skipped message keys
    pub fn clear_skipped_keys(&mut self) {
        // Zeroize keys before removing
        for (_, key) in &mut self.skipped_message_keys {
            key.zeroize();
        }
        self.skipped_message_keys.clear();
    }

    /// Set local DH key pair
    pub fn set_local_dh(&mut self, secret: StaticSecret) {
        let public = PublicKey::from(&secret);
        self.dh_local_bytes = public.as_bytes().to_vec();
        self.dh_local = Some(secret);
    }

    /// Set remote DH public key
    pub fn set_remote_dh(&mut self, public: PublicKey) {
        self.dh_remote_bytes = Some(public.as_bytes().to_vec());
        self.dh_remote = Some(public);
    }

    /// Restore DH keys from serialized bytes
    pub fn restore_dh_keys(&mut self) -> Result<(), &'static str> {
        // Restore local key
        if !self.dh_local_bytes.is_empty() {
            let arr: [u8; 32] = self.dh_local_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid local DH bytes length")?;
            self.dh_local = Some(StaticSecret::from(arr));
        }

        // Restore remote key
        if let Some(ref bytes) = self.dh_remote_bytes {
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid remote DH bytes length")?;
            self.dh_remote = Some(PublicKey::from(arr));
        }

        Ok(())
    }

    /// Check if state is valid for sending
    pub fn can_send(&self) -> bool {
        self.sending_chain.is_some() && self.dh_local.is_some()
    }

    /// Check if state is valid for receiving
    pub fn can_receive(&self) -> bool {
        self.receiving_chain.is_some() && self.dh_remote.is_some()
    }

    /// Get a summary of the state
    pub fn summary(&self) -> StateSummary {
        StateSummary {
            has_sending_chain: self.sending_chain.is_some(),
            has_receiving_chain: self.receiving_chain.is_some(),
            sending_index: self.sending_chain.as_ref().map(|c| c.index()).unwrap_or(0),
            receiving_index: self.receiving_chain.as_ref().map(|c| c.index()).unwrap_or(0),
            skipped_keys_count: self.skipped_keys_count(),
            has_local_dh: self.dh_local.is_some(),
            has_remote_dh: self.dh_remote.is_some(),
            age_secs: self.age_secs(),
            idle_secs: self.idle_secs(),
        }
    }
}

impl Clone for DoubleRatchetState {
    fn clone(&self) -> Self {
        // Manual clone because StaticSecret doesn't derive Clone
        let dh_local_clone = self.dh_local.as_ref().map(|dh| {
            let bytes = dh.to_bytes();
            StaticSecret::from(bytes)
        });

        let dh_remote_clone = self.dh_remote;

        Self {
            root_key: self.root_key,
            sending_chain: self.sending_chain.clone(),
            receiving_chain: self.receiving_chain.clone(),
            dh_local: dh_local_clone,
            dh_local_bytes: self.dh_local_bytes.clone(),
            dh_remote: dh_remote_clone,
            dh_remote_bytes: self.dh_remote_bytes.clone(),
            skipped_message_keys: self.skipped_message_keys.clone(),
            max_skip: self.max_skip,
            previous_counter: self.previous_counter,
            created_at: self.created_at,
            last_activity: self.last_activity,
            version: self.version,
        }
    }
}

impl Zeroize for DoubleRatchetState {
    fn zeroize(&mut self) {
        self.root_key.zeroize();
        self.sending_chain = None;
        self.receiving_chain = None;
        self.dh_local = None;
        self.dh_local_bytes.zeroize();
        self.dh_remote = None;
        if let Some(ref mut bytes) = self.dh_remote_bytes {
            bytes.zeroize();
        }
        for (_, key) in &mut self.skipped_message_keys {
            key.zeroize();
        }
        self.skipped_message_keys.clear();
        self.previous_counter = 0;
    }
}

impl ZeroizeOnDrop for DoubleRatchetState {}

impl Drop for DoubleRatchetState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// State summary for monitoring
#[derive(Clone, Debug)]
pub struct StateSummary {
    /// Whether sending chain exists
    pub has_sending_chain: bool,
    /// Whether receiving chain exists
    pub has_receiving_chain: bool,
    /// Current sending chain index
    pub sending_index: u64,
    /// Current receiving chain index
    pub receiving_index: u64,
    /// Number of skipped message keys
    pub skipped_keys_count: usize,
    /// Whether local DH key exists
    pub has_local_dh: bool,
    /// Whether remote DH key exists
    pub has_remote_dh: bool,
    /// State age in seconds
    pub age_secs: u64,
    /// Idle time in seconds
    pub idle_secs: u64,
}

/// Custom serialization for skipped message keys
mod skipped_keys_serde {
    use super::*;
    use serde::{Serialize, Deserialize, Serializer, Deserializer};

    #[derive(Serialize, Deserialize)]
    struct SkippedKeyEntry {
        pub_key: [u8; 32],
        msg_num: u64,
        msg_key: [u8; 32],
    }

    pub fn serialize<S>(map: &HashMap<([u8; 32], u64), [u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<SkippedKeyEntry> = map
            .iter()
            .map(|((pub_key, msg_num), msg_key)| SkippedKeyEntry {
                pub_key: *pub_key,
                msg_num: *msg_num,
                msg_key: *msg_key,
            })
            .collect();

        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<([u8; 32], u64), [u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries: Vec<SkippedKeyEntry> = Vec::deserialize(deserializer)?;

        let mut map = HashMap::new();
        for entry in entries {
            map.insert((entry.pub_key, entry.msg_num), entry.msg_key);
        }

        Ok(map)
    }
}

/// Custom serialization for bytes
mod serde_bytes {
    use serde::{Serializer, Deserializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_creation() {
        let state = DoubleRatchetState::new();
        assert_eq!(state.skipped_keys_count(), 0);
        assert!(!state.can_send());
        assert!(!state.can_receive());
    }

    #[test]
    fn test_skipped_keys() {
        let mut state = DoubleRatchetState::new();

        let pub_key = [1u8; 32];
        let msg_num = 100;
        let key = [2u8; 32];

        assert!(state.add_skipped_key(pub_key, msg_num, key));
        assert_eq!(state.skipped_keys_count(), 1);

        let retrieved = state.get_skipped_key(&pub_key, msg_num);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), &key);

        let removed = state.remove_skipped_key(&pub_key, msg_num);
        assert!(removed.is_some());
        assert_eq!(state.skipped_keys_count(), 0);
    }

    #[test]
    fn test_skipped_keys_limit() {
        let mut state = DoubleRatchetState::new();
        state.max_skip = 5;

        for i in 0..5 {
            assert!(state.add_skipped_key([i as u8; 32], i as u64, [i as u8; 32]));
        }

        // Should fail when limit reached
        assert!(!state.add_skipped_key([5u8; 32], 5, [5u8; 32]));
    }

    #[test]
    fn test_state_expiration() {
        let mut state = DoubleRatchetState::new();
        
        // New state should not be expired
        assert!(!state.is_expired());

        // Manually set last activity to 31 days ago
        state.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 31 * 86400;

        assert!(state.is_expired());
    }

    #[test]
    fn test_dh_key_management() {
        let mut state = DoubleRatchetState::new();

        let secret = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        state.set_local_dh(secret);

        assert!(!state.dh_local_bytes.is_empty());
        assert!(state.dh_local.is_some());

        let public = PublicKey::from(&StaticSecret::random_from_rng(&mut rand_core::OsRng));
        state.set_remote_dh(public);

        assert!(state.dh_remote_bytes.is_some());
        assert!(state.dh_remote.is_some());
    }

    #[test]
    fn test_restore_dh_keys() {
        let mut state = DoubleRatchetState::new();

        let secret = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        state.set_local_dh(secret);

        let public = PublicKey::from(&StaticSecret::random_from_rng(&mut rand_core::OsRng));
        state.set_remote_dh(public);

        // Clear the keys
        state.dh_local = None;
        state.dh_remote = None;

        // Restore
        assert!(state.restore_dh_keys().is_ok());
        assert!(state.dh_local.is_some());
        assert!(state.dh_remote.is_some());
    }

    #[test]
    fn test_state_summary() {
        let state = DoubleRatchetState::new();
        let summary = state.summary();

        assert!(!summary.has_sending_chain);
        assert!(!summary.has_receiving_chain);
        assert_eq!(summary.skipped_keys_count, 0);
    }

    #[test]
    fn test_state_zeroize() {
        let mut state = DoubleRatchetState::new();
        state.root_key = [0x42u8; 32];
        
        state.zeroize();
        
        assert!(state.root_key.iter().all(|&b| b == 0));
        assert!(state.skipped_message_keys.is_empty());
    }
}
