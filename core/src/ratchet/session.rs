//! Double Ratchet Session - Production Hardened v9
//!
//! FIXES:
//! - HKDF: Two expand() on same PRK replaced with single 64-byte expand + split
//! - Encryptor initial_message_number=u64::MAX -> 0 (correct semantics)
//! - skip_message_keys: all unwrap() replaced with proper ? propagation
//! - perform_handshake: shared_secret no longer returned to caller

use super::{ChainKey, DoubleRatchetState, RatchetHeader, RatchetMessage, RatchetConfig};
use super::super::crypto::{Encryptor, constant_time_eq, SecureRandom, RatchetKdf};
use super::super::error::{ProtocolError, ProtocolResult};
use super::super::validation::{validate_message, validate_associated_data};
use crate::Config;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use parking_lot::RwLock;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Double Ratchet Session - manages state and cryptographic operations for a secure channel.
pub struct DoubleRatchetSession {
    state: RwLock<DoubleRatchetState>,
    config: Config,
    _ratchet_config: RatchetConfig,
    session_id: String,
    peer_id: Option<String>,
    messages_sent: std::sync::atomic::AtomicU64,
    messages_received: std::sync::atomic::AtomicU64,
    created_at: std::time::Instant,
}

#[allow(missing_docs)]
impl DoubleRatchetSession {
    pub fn new(config: Config) -> ProtocolResult<Self> {
        let dh_local = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let dh_local_bytes = dh_local.to_bytes().to_vec();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let state = DoubleRatchetState {
            root_key: [0u8; 32],
            sending_chain: None,
            receiving_chain: None,
            dh_local: Some(dh_local),
            dh_local_bytes,
            dh_remote: None,
            dh_remote_bytes: None,
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
            created_at: now,
            last_activity: now,
            version: DoubleRatchetState::CURRENT_VERSION,
        };

        let session_id = Self::generate_session_id()?;
        Ok(Self {
            state: RwLock::new(state),
            config: config.clone(),
            _ratchet_config: RatchetConfig::default(),
            session_id,
            peer_id: None,
            messages_sent: std::sync::atomic::AtomicU64::new(0),
            messages_received: std::sync::atomic::AtomicU64::new(0),
            created_at: std::time::Instant::now(),
        })
    }

    /// FIX: HKDF now uses single 64-byte expand then splits into root_key + chain_key.
    /// Previously two separate expand() calls on the same PRK with no salt were used,
    /// which while not catastrophically broken, is non-standard and wastes KDF strength.
    pub fn from_shared_secret(
        shared_secret: &[u8; 32],
        local_dh: StaticSecret,
        remote_dh: PublicKey,
        config: Config,
        initiator: bool,
    ) -> ProtocolResult<Self> {
        if shared_secret.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidArgument);
        }

        // FIX: Single HKDF expand for 64 bytes, split into root_key (32) + chain_key (32)
        let hkdf = Hkdf::<Sha256>::new(Some(b"SibnaSession_v9"), shared_secret);
        let mut okm = [0u8; 64];
        hkdf.expand(b"SibnaRootAndChainKey_v9", &mut okm)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        let mut root_key = [0u8; 32];
        let mut chain_key = [0u8; 32];
        root_key.copy_from_slice(&okm[..32]);
        chain_key.copy_from_slice(&okm[32..]);
        okm.zeroize();

        let (sending_chain, receiving_chain) = if initiator {
            (Some(ChainKey::new(chain_key)), None)
        } else {
            (None, Some(ChainKey::new(chain_key)))
        };

        let dh_local_bytes = local_dh.to_bytes().to_vec();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let state = DoubleRatchetState {
            root_key,
            sending_chain,
            receiving_chain,
            dh_local: Some(local_dh),
            dh_local_bytes,
            dh_remote: Some(remote_dh),
            dh_remote_bytes: Some(remote_dh.as_bytes().to_vec()),
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
            created_at: now,
            last_activity: now,
            version: DoubleRatchetState::CURRENT_VERSION,
        };

        let session_id = Self::generate_session_id()?;
        Ok(Self {
            state: RwLock::new(state),
            config: config.clone(),
            _ratchet_config: RatchetConfig::default(),
            session_id,
            peer_id: None,
            messages_sent: std::sync::atomic::AtomicU64::new(0),
            messages_received: std::sync::atomic::AtomicU64::new(0),
            created_at: std::time::Instant::now(),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        validate_message(plaintext).map_err(|_| ProtocolError::InvalidMessage)?;
        validate_associated_data(associated_data).map_err(|_| ProtocolError::InvalidArgument)?;

        let mut state = self.state.write();

        if state.sending_chain.as_ref().map(|c| c.needs_rotation()).unwrap_or(true) {
            self.perform_dh_ratchet(&mut state)?;
        }

        let dh_pub = state.dh_local.as_ref()
            .map(PublicKey::from)
            .ok_or(ProtocolError::InvalidState)?;

        let sending_chain = state.sending_chain.as_mut()
            .ok_or(ProtocolError::InvalidState)?;

        let message_key = sending_chain.next_message_key()
            .ok_or(ProtocolError::InvalidState)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let header = RatchetHeader {
            dh_public: *dh_pub.as_bytes(),
            message_number: sending_chain.index() - 1,
            previous_chain_length: state.previous_counter,
            timestamp,
        };

        header.validate()?;

        // FIX: initial_message_number=0, not u64::MAX. The Encryptor's counter
        // tracks its own sequence; using MAX was a logic error that could cause
        // wrapping issues and bypasses replay detection on first message.
        let mut encryptor = Encryptor::new(&message_key, 0)
            .map_err(ProtocolError::from)?;

        let header_bytes = header.to_bytes();
        let mut final_ad = Vec::with_capacity(associated_data.len() + header_bytes.len());
        final_ad.extend_from_slice(associated_data);
        final_ad.extend_from_slice(&header_bytes);

        let ciphertext = encryptor.encrypt_message(plaintext, &final_ad)
            .map_err(ProtocolError::from)?;

        let message = RatchetMessage { header, ciphertext };

        state.touch();
        self.messages_sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        Ok(message.to_bytes())
    }

    pub fn decrypt(&self, message: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if message.len() < 48 + 29 {
            return Err(ProtocolError::InvalidMessage);
        }

        let ratchet_message = RatchetMessage::from_bytes(message)?;
        let header = ratchet_message.header;
        header.validate()?;

        let mut state = self.state.write();
        let remote_dh = PublicKey::from(header.dh_public);

        let key_tuple = (header.dh_public, header.message_number);
        if let Some(&mk) = state.skipped_message_keys.get(&key_tuple) {
            return self.decrypt_with_key(
                &mk, &ratchet_message.ciphertext, associated_data,
                &header, &mut state, &key_tuple,
            );
        }

        let needs_ratchet = match state.dh_remote {
            None => true,
            Some(ref current) => !constant_time_eq(current.as_bytes(), remote_dh.as_bytes()),
        };

        if needs_ratchet {
            if let Some(prev_counter) = state.sending_chain.as_ref().map(|c| c.index()) {
                state.previous_counter = prev_counter;
            }
            self.skip_message_keys(&mut state, header.previous_chain_length)?;
            self.dh_ratchet(&mut state, remote_dh)?;
        }

        self.skip_message_keys(&mut state, header.message_number)?;

        let mk = {
            let receiving_chain = state.receiving_chain.as_mut()
                .ok_or(ProtocolError::InvalidState)?;
            if header.message_number < receiving_chain.index() {
                return Err(ProtocolError::ReplayAttackDetected);
            }
            receiving_chain.next_message_key().ok_or(ProtocolError::InvalidState)?
        };

        let result = self.decrypt_with_key(
            &mk, &ratchet_message.ciphertext, associated_data,
            &header, &mut state, &key_tuple,
        );

        state.touch();
        self.messages_received.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        result
    }

    fn decrypt_with_key(
        &self, key: &[u8; 32], ciphertext: &[u8], associated_data: &[u8],
        header: &RatchetHeader, state: &mut DoubleRatchetState,
        key_tuple: &([u8; 32], u64),
    ) -> ProtocolResult<Vec<u8>> {
        // FIX: initial_message_number=0 (consistent with encrypt)
        let mut encryptor = Encryptor::new(key, 0).map_err(ProtocolError::from)?;

        let header_bytes = header.to_bytes();
        let mut full_ad = Vec::with_capacity(associated_data.len() + header_bytes.len());
        full_ad.extend_from_slice(associated_data);
        full_ad.extend_from_slice(&header_bytes);

        let result = encryptor.decrypt_message(ciphertext, &full_ad).map_err(ProtocolError::from);

        if result.is_ok() {
            state.skipped_message_keys.remove(key_tuple);
        }

        result
    }

    /// FIX: All unwrap() replaced with ? operator - no more panics on malformed messages.
    fn skip_message_keys(&self, state: &mut DoubleRatchetState, until_n: u64) -> ProtocolResult<()> {
        if state.receiving_chain.is_none() { return Ok(()); }

        let current_index = state.receiving_chain
            .as_ref()
            .ok_or(ProtocolError::InvalidState)?
            .index();

        if until_n > current_index + state.max_skip as u64 {
            return Err(ProtocolError::MaxSkippedMessagesExceeded);
        }

        while state.receiving_chain
            .as_ref()
            .ok_or(ProtocolError::InvalidState)?
            .index() < until_n
        {
            let mk = state.receiving_chain
                .as_mut()
                .ok_or(ProtocolError::InvalidState)?
                .next_message_key()
                .ok_or(ProtocolError::InvalidState)?;

            let dh_remote = state.dh_remote.ok_or(ProtocolError::InvalidState)?;

            let key_index = state.receiving_chain
                .as_ref()
                .ok_or(ProtocolError::InvalidState)?
                .index() - 1;

            if !state.add_skipped_key(*dh_remote.as_bytes(), key_index, mk) {
                return Err(ProtocolError::MaxSkippedMessagesExceeded);
            }
        }
        Ok(())
    }

    fn dh_ratchet(&self, state: &mut DoubleRatchetState, remote_dh: PublicKey) -> ProtocolResult<()> {
        state.previous_counter = state.sending_chain.as_ref().map(|c| c.index()).unwrap_or(0);
        state.set_remote_dh(remote_dh);

        let dh_local = state.dh_local.as_ref().ok_or(ProtocolError::InvalidState)?;
        let shared_secret = dh_local.diffie_hellman(&remote_dh);
        let (root_key, receiving_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret.as_bytes())?;
        state.root_key = *root_key;
        state.receiving_chain = Some(ChainKey::new(*receiving_key));

        let new_local = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let shared_secret_send = new_local.diffie_hellman(&remote_dh);
        let (root_key, sending_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret_send.as_bytes())?;
        state.root_key = *root_key;
        state.sending_chain = Some(ChainKey::new(*sending_key));
        state.set_local_dh(new_local);

        Ok(())
    }

    fn perform_dh_ratchet(&self, state: &mut DoubleRatchetState) -> ProtocolResult<()> {
        let new_local = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        if let Some(remote_dh) = state.dh_remote {
            let shared_secret = new_local.diffie_hellman(&remote_dh);
            let (root_key, sending_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret.as_bytes())?;
            state.root_key = *root_key;
            state.sending_chain = Some(ChainKey::new(*sending_key));
        }
        state.set_local_dh(new_local);
        Ok(())
    }

    fn generate_session_id() -> ProtocolResult<String> {
        let mut rng = SecureRandom::new()?;
        let bytes = rng.gen_bytes(16);
        Ok(hex::encode(bytes))
    }

    pub fn session_id(&self) -> &str { &self.session_id }
    pub fn set_peer_id(&mut self, peer_id: String) { self.peer_id = Some(peer_id); }
    pub fn peer_id(&self) -> Option<&str> { self.peer_id.as_deref() }
    pub fn message_stats(&self) -> (u64, u64) {
        (
            self.messages_sent.load(std::sync::atomic::Ordering::Relaxed),
            self.messages_received.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
    pub fn age(&self) -> std::time::Duration { self.created_at.elapsed() }
    pub fn state_summary(&self) -> super::StateSummary { self.state.read().summary() }
    /// Check if the session has expired
    pub fn is_expired(&self) -> bool { self.state.read().is_expired() }

    /// Serialize the current session state to bytes.
    /// 
    /// Used for persistent storage of ratchet state.
    pub fn serialize_state(&self) -> ProtocolResult<Vec<u8>> {
        let state = self.state.read();
        bincode::serialize(&*state)
            .map_err(|_| ProtocolError::SerializationError)
    }

    /// Restore session state from serialized bytes.
    pub fn deserialize_state(&self, data: &[u8]) -> ProtocolResult<()> {
        let mut state = self.state.write();
        let mut loaded: DoubleRatchetState = bincode::deserialize(data)
            .map_err(|_| ProtocolError::DeserializationError)?;
        loaded.restore_dh_keys().map_err(|_| ProtocolError::DeserializationError)?;
        loaded.max_skip = self.config.max_skipped_messages;
        *state = loaded;
        Ok(())
    }
}


impl Zeroize for DoubleRatchetSession {
    fn zeroize(&mut self) {
        // state contains ZeroizeOnDrop fields (root_key, chain keys, DH keys)
        // They are zeroed when state is dropped via DoubleRatchetState::zeroize()
        if let Some(mut state) = self.state.try_write() {
            state.zeroize();
        }
    }
}

impl Drop for DoubleRatchetSession {
    fn drop(&mut self) {}
}
impl ZeroizeOnDrop for DoubleRatchetSession {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        assert!(DoubleRatchetSession::new(Config::default()).is_ok());
    }

    #[test]
    fn test_session_from_shared_secret() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];
        let local_dh = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let remote_dh = PublicKey::from(&StaticSecret::random_from_rng(&mut rand_core::OsRng));
        assert!(DoubleRatchetSession::from_shared_secret(&shared_secret, local_dh, remote_dh, config, true).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);

        let s1 = DoubleRatchetSession::from_shared_secret(&shared_secret, sk1, pk2, config.clone(), true).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(&shared_secret, sk2, pk1, config, false).unwrap();

        let plaintext = b"Hello Production!";
        let ad = b"aad";
        let ct = s1.encrypt(plaintext, ad).unwrap();
        let pt = s2.decrypt(&ct, ad).unwrap();
        assert_eq!(plaintext.to_vec(), pt);
    }

    #[test]
    fn test_replay_protection() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);
        let s1 = DoubleRatchetSession::from_shared_secret(&shared_secret, sk1, pk2, config.clone(), true).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(&shared_secret, sk2, pk1, config, false).unwrap();
        let ct = s1.encrypt(b"test", b"ad").unwrap();
        let _ = s2.decrypt(&ct, b"ad").unwrap();
        assert!(s2.decrypt(&ct, b"ad").is_err());
    }
}
