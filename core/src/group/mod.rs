//! Group Messaging - Sender Keys Implementation - Hardened Edition
//!
//! Implements the Sender Keys protocol for efficient group encryption.
//! Based on Signal's group messaging design with security enhancements.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::{CryptoHandler, SecureRandom, constant_time_eq};

/// Group ID type
pub type GroupId = [u8; 32];

/// Maximum group size
pub const MAX_GROUP_SIZE: usize = 1000;

/// Maximum message size for group messages
pub const MAX_GROUP_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Sender Key for group messaging
#[derive(Serialize, Deserialize, Clone)]
pub struct SenderKey {
    /// Chain key for message derivation
    #[serde(with = "serde_bytes")]
    pub chain_key: Vec<u8>,
    /// Current message number
    pub message_number: u32,
    /// Expiration timestamp
    pub expiration: Option<u64>,
    /// Key creation timestamp
    pub created_at: u64,
    /// Key ID for rotation
    pub key_id: u32,
}

impl SenderKey {
    /// Default key expiration (7 days)
    pub const DEFAULT_EXPIRATION_SECS: u64 = 7 * 86400;

    /// Create a new sender key
    pub fn new(key_id: u32) -> ProtocolResult<Self> {
        let mut rng = SecureRandom::new()?;
        let mut chain_key = [0u8; 32];
        rng.fill_bytes(&mut chain_key);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        Ok(Self {
            chain_key: chain_key.to_vec(),
            message_number: 0,
            expiration: Some(created_at + Self::DEFAULT_EXPIRATION_SECS),
            created_at,
            key_id,
        })
    }

    /// Create a new sender key with custom expiration
    pub fn with_expiration(key_id: u32, expiration_secs: u64) -> ProtocolResult<Self> {
        let mut key = Self::new(key_id)?;
        key.expiration = Some(key.created_at + expiration_secs);
        Ok(key)
    }

    /// Derive next message key
    pub fn next_message_key(&mut self) -> ProtocolResult<[u8; 32]> {
        // Check expiration
        if let Some(expiration) = self.expiration {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ProtocolError::InternalError)?
                .as_secs();
            
            if now > expiration {
                return Err(ProtocolError::Expired);
            }
        }

        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);
        
        // Derive message key
        let mut message_key = [0u8; 32];
        hkdf.expand(b"SibnaGroupMessageKey_v9", &mut message_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
        
        // Advance chain key
        let mut next_chain = [0u8; 32];
        hkdf.expand(b"SibnaGroupChainKey_v9", &mut next_chain)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
        
        // Securely update chain key
        self.chain_key.zeroize();
        self.chain_key = next_chain.to_vec();
        self.message_number += 1;
        
        Ok(message_key)
    }

    /// Check if key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expiration) = self.expiration {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            return now > expiration;
        }
        false
    }

    /// Get key age in seconds
    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        now.saturating_sub(self.created_at)
    }

    /// Rotate to a new key
    pub fn rotate(&mut self) -> ProtocolResult<()> {
        let new_key = Self::new(self.key_id.wrapping_add(1))?;
        *self = new_key;
        Ok(())
    }
}

impl Zeroize for SenderKey {
    fn zeroize(&mut self) {
        self.chain_key.zeroize();
        self.message_number = 0;
    }
}

impl ZeroizeOnDrop for SenderKey {}

impl Drop for SenderKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Sender Key Distribution Message
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SenderKeyMessage {
    /// Group ID
    pub group_id: GroupId,
    /// Sender's public key
    pub sender_public_key: [u8; 32],
    /// Encrypted sender key
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
    /// Signature
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Key ID
    pub key_id: u32,
}

impl SenderKeyMessage {
    /// Create a new sender key message
    pub fn new(
        group_id: GroupId,
        sender_public_key: [u8; 32],
        encrypted_key: Vec<u8>,
        signature: Vec<u8>,
        key_id: u32,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            group_id,
            sender_public_key,
            encrypted_key,
            signature,
            timestamp,
            key_id,
        }
    }

    /// Validate the message
    pub fn validate(&self) -> ProtocolResult<()> {
        // Check timestamp (not older than 1 hour, not in future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        if self.timestamp > now + 300 { // 5 minutes in future
            return Err(ProtocolError::InvalidMessage);
        }

        if now > self.timestamp + 3600 { // 1 hour old
            return Err(ProtocolError::Expired);
        }

        Ok(())
    }
}

/// Group Session State
pub struct GroupSession {
    /// Group ID
    pub group_id: GroupId,
    /// Our sender key for this group
    pub our_sender_key: Option<SenderKey>,
    /// Sender keys from other members (public_key -> key)
    pub sender_keys: HashMap<[u8; 32], SenderKey>,
    /// Group members' public keys
    pub members: Vec<[u8; 32]>,
    /// Current epoch (incremented on member change)
    pub epoch: u64,
    /// Group name (optional)
    pub name: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Maximum group size
    pub max_size: usize,
}

impl GroupSession {
    /// Create a new group session
    pub fn new(group_id: GroupId, max_size: usize) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            group_id,
            our_sender_key: None,
            sender_keys: HashMap::new(),
            members: Vec::new(),
            epoch: 0,
            name: None,
            created_at: now,
            last_activity: now,
            max_size: max_size.min(MAX_GROUP_SIZE),
        }
    }

    /// Initialize sender key for this group
    pub fn initialize_sender_key(&mut self) -> ProtocolResult<()> {
        self.our_sender_key = Some(SenderKey::new(1)?);
        self.touch();
        Ok(())
    }

    /// Add a member to the group
    pub fn add_member(&mut self, public_key: [u8; 32]) -> ProtocolResult<()> {
        // Check group size
        if self.members.len() >= self.max_size {
            return Err(ProtocolError::InvalidArgument);
        }

        // Check for duplicate
        if self.members.contains(&public_key) {
            return Err(ProtocolError::InvalidArgument);
        }

        self.members.push(public_key);
        self.epoch += 1;
        self.touch();
        Ok(())
    }

    /// Remove a member from the group
    pub fn remove_member(&mut self, public_key: &[u8; 32]) {
        self.members.retain(|k| !constant_time_eq(k, public_key));
        self.sender_keys.remove(public_key);
        self.epoch += 1;
        self.touch();
    }

    /// Encrypt a group message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> ProtocolResult<GroupMessage> {
        // Validate message size
        if plaintext.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::InvalidArgument);
        }

        let sender_key = self.our_sender_key.as_mut()
            .ok_or_else(|| ProtocolError::InvalidState)?;
        
        // Check if key needs rotation
        if sender_key.message_number > 1000 || sender_key.is_expired() {
            sender_key.rotate()?;
        }
        
        let message_key = sender_key.next_message_key()?;
        
        let crypto = CryptoHandler::new(&message_key)?;
        let ciphertext = crypto.encrypt(plaintext, &self.group_id)?;
        
        let message = GroupMessage {
            group_id: self.group_id,
            sender_key_id: sender_key.key_id,
            message_number: sender_key.message_number - 1,
            ciphertext,
            epoch: self.epoch,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.touch();
        
        Ok(message)
    }

    /// Decrypt a group message
    pub fn decrypt(&mut self, message: &GroupMessage, sender_public_key: &[u8; 32]) -> ProtocolResult<Vec<u8>> {
        // Validate message
        message.validate()?;

        // Check group ID
        if !constant_time_eq(&message.group_id, &self.group_id) {
            return Err(ProtocolError::InvalidMessage);
        }

        // Check epoch
        if message.epoch < self.epoch {
            return Err(ProtocolError::InvalidMessage);
        }

        let sender_key = self.sender_keys.get_mut(sender_public_key)
            .ok_or_else(|| ProtocolError::KeyNotFound)?;

        // Check if key ID matches
        if sender_key.key_id != message.sender_key_id {
            return Err(ProtocolError::InvalidMessage);
        }

        // FIX: Bound the number of skipped messages to prevent DoS.
        // An attacker sending message_number=2^32-1 would exhaust CPU.
        const MAX_SKIP_GROUP: u32 = 500;
        if message.message_number > sender_key.message_number + MAX_SKIP_GROUP {
            return Err(ProtocolError::MaxSkippedMessagesExceeded);
        }
        // Derive message keys until we reach the target
        while sender_key.message_number < message.message_number {
            sender_key.next_message_key()?;
        }
        
        let message_key = sender_key.next_message_key()?;
        let crypto = CryptoHandler::new(&message_key)?;
        
        let plaintext = crypto.decrypt(&message.ciphertext, &self.group_id)
            .map_err(ProtocolError::from)?;
        
        self.touch();
        
        Ok(plaintext)
    }

    /// Import a sender key from another member
    pub fn import_sender_key(&mut self, public_key: [u8; 32], key: SenderKey) -> ProtocolResult<()> {
        // Validate key
        if key.is_expired() {
            return Err(ProtocolError::Expired);
        }

        self.sender_keys.insert(public_key, key);
        self.touch();
        Ok(())
    }

    /// Update last activity
    fn touch(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Get member count
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Check if a member exists
    pub fn has_member(&self, public_key: &[u8; 32]) -> bool {
        self.members.iter().any(|m| constant_time_eq(m, public_key))
    }

    /// Get session age in seconds
    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        now.saturating_sub(self.created_at)
    }
}

impl Zeroize for GroupSession {
    fn zeroize(&mut self) {
        self.group_id.zeroize();
        self.our_sender_key = None;
        self.sender_keys.clear();
        self.members.clear();
        self.epoch = 0;
    }
}

impl ZeroizeOnDrop for GroupSession {}

/// Group Message
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GroupMessage {
    /// Group ID
    pub group_id: GroupId,
    /// Sender key identifier
    pub sender_key_id: u32,
    /// Message number
    pub message_number: u32,
    /// Encrypted content
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// Group epoch
    pub epoch: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl GroupMessage {
    /// Validate the message
    pub fn validate(&self) -> ProtocolResult<()> {
        // Check timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        if self.timestamp > now + 300 { // 5 minutes in future
            return Err(ProtocolError::InvalidMessage);
        }

        if now > self.timestamp + 86400 { // 1 day old
            return Err(ProtocolError::Expired);
        }

        // Check ciphertext size
        if self.ciphertext.len() > MAX_GROUP_MESSAGE_SIZE + 1024 {
            return Err(ProtocolError::InvalidMessage);
        }

        Ok(())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> ProtocolResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|_| ProtocolError::SerializationError)
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        bincode::deserialize(data)
            .map_err(|_| ProtocolError::DeserializationError)
    }
}

/// Group Manager - Handles multiple groups
pub struct GroupManager {
    groups: HashMap<GroupId, GroupSession>,
    master_key: [u8; 32],
    max_groups: usize,
}

impl GroupManager {
    /// Maximum number of groups per user
    pub const DEFAULT_MAX_GROUPS: usize = 100;

    /// Create a new group manager
    pub fn new(master_key: &[u8; 32]) -> ProtocolResult<Self> {
        Ok(Self {
            groups: HashMap::new(),
            master_key: *master_key,
            max_groups: Self::DEFAULT_MAX_GROUPS,
        })
    }

    /// Create a new group
    /// Create a new group session
    pub fn create_group(&mut self, group_id: GroupId) -> ProtocolResult<&mut GroupSession> {
        // Check group limit
        if self.groups.len() >= self.max_groups {
            return Err(ProtocolError::InvalidArgument);
        }

        let mut session = GroupSession::new(group_id, MAX_GROUP_SIZE);
        session.initialize_sender_key()?;
        
        self.groups.insert(group_id, session);
        self.groups.get_mut(&group_id).ok_or(crate::error::ProtocolError::InternalError)
    }

    /// Get a group session
    pub fn get_group(&self, group_id: &GroupId) -> Option<&GroupSession> {
        self.groups.get(group_id)
    }

    /// Get a mutable group session
    pub fn get_group_mut(&mut self, group_id: &GroupId) -> Option<&mut GroupSession> {
        self.groups.get_mut(group_id)
    }

    /// Leave a group
    pub fn leave_group(&mut self, group_id: &GroupId) {
        self.groups.remove(group_id);
    }

    /// List all groups
    pub fn list_groups(&self) -> Vec<&GroupId> {
        self.groups.keys().collect()
    }

    /// Get group count
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Prune inactive groups
    pub fn prune_inactive(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.groups.retain(|_, g| {
            now - g.last_activity < max_age_secs
        });
    }
}

impl Zeroize for GroupManager {
    fn zeroize(&mut self) {
        self.master_key.zeroize();
        for (_, group) in &mut self.groups {
            group.zeroize();
        }
        self.groups.clear();
    }
}

impl ZeroizeOnDrop for GroupManager {}

impl Drop for GroupManager {
    fn drop(&mut self) {
        self.zeroize();
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
    fn test_sender_key_creation() {
        let key = SenderKey::new(1);
        assert!(key.is_ok());
    }

    #[test]
    fn test_sender_key_derivation() {
        let mut key = SenderKey::new(1).unwrap();
        
        let mk1 = key.next_message_key().unwrap();
        let mk2 = key.next_message_key().unwrap();
        
        assert_ne!(mk1, mk2);
        assert_eq!(key.message_number, 2);
    }

    #[test]
    fn test_sender_key_expiration() {
        let mut key = SenderKey::with_expiration(1, 1).unwrap(); // 1 second expiration
        
        // Should work initially
        assert!(key.next_message_key().is_ok());
        
        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Should fail after expiration
        assert!(key.is_expired());
        assert!(key.next_message_key().is_err());
    }

    #[test]
    fn test_group_session_creation() {
        let group_id = [0u8; 32];
        let mut session = GroupSession::new(group_id, 100);
        
        assert!(session.initialize_sender_key().is_ok());
        assert!(session.our_sender_key.is_some());
    }

    #[test]
    fn test_group_encryption() {
        let group_id = [0x42u8; 32];
        let mut session = GroupSession::new(group_id, 100);
        session.initialize_sender_key().unwrap();
        
        let plaintext = b"Hello Group!";
        let message = session.encrypt(plaintext);
        
        assert!(message.is_ok());
    }

    #[test]
    fn test_group_member_management() {
        let group_id = [0u8; 32];
        let mut session = GroupSession::new(group_id, 100);
        
        let member1 = [1u8; 32];
        let member2 = [2u8; 32];
        
        assert!(session.add_member(member1).is_ok());
        assert!(session.add_member(member2).is_ok());
        assert_eq!(session.member_count(), 2);
        
        session.remove_member(&member1);
        assert_eq!(session.member_count(), 1);
    }

    #[test]
    fn test_group_size_limit() {
        let group_id = [0u8; 32];
        let mut session = GroupSession::new(group_id, 2);
        
        assert!(session.add_member([1u8; 32]).is_ok());
        assert!(session.add_member([2u8; 32]).is_ok());
        assert!(session.add_member([3u8; 32]).is_err()); // Should fail
    }

    #[test]
    fn test_group_manager() {
        let master_key = [0x42u8; 32];
        let mut manager = GroupManager::new(&master_key).unwrap();
        
        let group_id = [0u8; 32];
        assert!(manager.create_group(group_id).is_ok());
        assert_eq!(manager.group_count(), 1);
        
        let group = manager.get_group(&group_id);
        assert!(group.is_some());
    }

    #[test]
    fn test_group_message_roundtrip() {
        let group_id = [0x42u8; 32];
        let message = GroupMessage {
            group_id,
            sender_key_id: 1,
            message_number: 100,
            ciphertext: vec![1, 2, 3, 4, 5],
            epoch: 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let bytes = message.to_bytes().unwrap();
        let parsed = GroupMessage::from_bytes(&bytes).unwrap();
        
        assert_eq!(message.ciphertext, parsed.ciphertext);
        assert_eq!(message.sender_key_id, parsed.sender_key_id);
    }
}
