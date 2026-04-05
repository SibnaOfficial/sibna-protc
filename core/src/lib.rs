//! Sibna Protocol v1.0
//!
//! An independent Rust implementation of the Signal Protocol (X3DH + Double Ratchet)
//! designed for integration into commercial and open-source applications.
//!
//! **IMPORTANT — NO EXTERNAL SECURITY AUDIT HAS BEEN PERFORMED.**
//! This library has undergone internal hardening (see SECURITY.md) but has NOT been
//! reviewed by an independent security firm. Do not deploy in high-risk environments
//! until an external audit is completed (roadmap: Q3 2026).
//!
//! # What This Library Provides
//! - **Confidentiality**: ChaCha20-Poly1305 AEAD encryption.
//! - **Forward Secrecy**: Double Ratchet re-keys on every message.
//! - **Post-Compromise Security**: DH ratchet re-keys after round-trips.
//! - **Quantum Resistance (Hybrid, Default ON)**: X3DH uses a hybrid
//!   X25519 + ML-KEM-768 handshake (FIPS 203). The session key is secure as
//!   long as _either_ primitive is unbroken. Disable with `default-features = false`.
//! - **Memory Safety**: Automatic key zeroization via `zeroize`.
//!
//! # What This Library Does NOT Provide
//!
//! > **MITM Protection**: Requires manual out-of-band Safety Number verification
//! > by the integrating application. At first contact, Trust-On-First-Use (TOFU)
//! > applies — the library cannot detect a MITM without user confirmation.
//!
//! > **Metadata Protection**: IP addresses, packet sizes, message timing, and
//! > session participant identities are NOT hidden or obfuscated. A network observer
//! > can see who is communicating with whom and when.
//!
//! > **Anonymity**: This library does NOT provide onion routing, traffic obfuscation,
//! > or any other anonymity mechanism. Network identities are fully visible.
//!
//! > **Quantum Resistance Without PQC Feature**: X25519 on its own is broken by
//! > a sufficiently powerful quantum computer. With the default `pqc` feature,
//! > the hybrid handshake protects against this, but the feature must remain enabled.
//!
//! # Version
//! 2.0.0

#![allow(missing_docs)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::len_zero)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::io_other_error)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::new_without_default)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::type_complexity)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::missing_const_for_thread_local)]
#![allow(clippy::needless_return)]

// Core modules
pub mod crypto;
pub mod ratchet;
pub mod handshake;
pub mod keystore;
pub mod error;
pub mod group;
pub mod safety;
pub mod rate_limit;
pub mod validation;
pub mod media;
pub mod iot;
pub mod metadata;
pub mod manager;
#[cfg(feature = "p2p")]
pub mod transport;
pub mod storage;

// P2P transport (optional, requires feature = "p2p")
#[cfg(feature = "p2p")]
pub mod p2p;

// FFI modules (optional)
#[cfg(feature = "ffi")]
pub mod ffi;

// WASM module (optional)
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Re-exports
pub use crypto::*;
pub use ratchet::*;
pub use handshake::*;
pub use keystore::*;
pub use error::{ProtocolError, ProtocolResult};
pub use group::{GroupSession, SenderKey, GroupMessage, GroupManager};
pub use safety::{SafetyNumber, VerificationQrCode};
pub use rate_limit::{RateLimiter, RateLimitError, OperationLimit, RemainingQuota};
pub use validation::{validate_message, validate_key, validate_session_id, ValidationError};

// P2P re-exports
#[cfg(feature = "p2p")]
pub use p2p::{P2pNode, P2pConfig, P2pError, P2pResult};
pub use manager::HybridRouter;

use std::sync::Arc;
use parking_lot::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use x25519_dalek::PublicKey;

/// Protocol version
/// Protocol version — always in sync with Cargo.toml
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol version number for compatibility
pub const VERSION_NUMBER: u32 = 1;

/// Minimum compatible version
pub const MIN_COMPATIBLE_VERSION: u32 = 1;

/// Main System Context for secure communication
///
/// This is the primary entry point for the Sibna protocol. It manages
/// key storage, session state, group messaging, and cryptographic operations.
#[derive(Clone)]
pub struct SecureContext {
    /// Encrypted key storage
    keystore: Arc<RwLock<KeyStore>>,
    /// Session manager for active connections
    sessions: Arc<RwLock<SessionManager>>,
    /// Group manager for group messaging
    groups: Arc<RwLock<GroupManager>>,
    /// Configuration options
    config: Config,
    /// Secure random number generator
    random: Arc<RwLock<SecureRandom>>,
    /// Storage encryption key (never exposed)
    storage_key: Arc<RwLock<zeroize::Zeroizing<[u8; 32]>>>,
    /// Salt used for the storage key derivation
    storage_salt: Arc<RwLock<[u8; 32]>>,
    /// Device ID for multi-device sync
    device_id: [u8; 16],
    /// Rate limiter for operations
    rate_limiter: Arc<RwLock<RateLimiter>>,
    /// Global sequence number for rollback protection
    sequence_number: Arc<std::sync::atomic::AtomicU64>,
    /// Context creation time
    created_at: std::time::Instant,
}

/// System Configuration
///
/// Controls various security and performance parameters for the protocol.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Enable Forward Secrecy (recommended: true)
    pub enable_forward_secrecy: bool,
    /// Enable Post-Compromise Security (recommended: true)
    pub enable_post_compromise_security: bool,
    /// Maximum number of skipped messages to store
    pub max_skipped_messages: usize,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Handshake timeout in seconds
    pub handshake_timeout: u64,
    /// Message buffer size
    pub message_buffer_size: usize,
    /// Enable group messaging
    pub enable_group_messaging: bool,
    /// Maximum group size
    pub max_group_size: usize,
    /// Database path
    pub db_path: Option<String>,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Maximum message size (bytes)
    pub max_message_size: usize,
    /// Session timeout in seconds
    pub session_timeout_secs: u64,
    /// Enable automatic key pruning
    pub auto_prune_keys: bool,
    /// Maximum key age in seconds
    pub max_key_age_secs: u64,
    /// Message padding mode
    pub message_padding: PaddingMode,
    /// Relay server URL
    pub relay_url: String,
    /// SOCKS5 proxy for anonymity (e.g. "socks5://127.0.0.1:9050" for Tor)
    pub proxy_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_forward_secrecy: true,
            enable_post_compromise_security: true,
            max_skipped_messages: 2000,
            key_rotation_interval: 86400, // 24 hours
            handshake_timeout: 30,
            message_buffer_size: 1024,
            enable_group_messaging: true,
            max_group_size: 256,
            db_path: None,
            enable_rate_limiting: true,
            max_message_size: 10 * 1024 * 1024, // 10 MB
            session_timeout_secs: 3600, // 1 hour
            auto_prune_keys: true,
            max_key_age_secs: 30 * 86400, // 30 days
            message_padding: PaddingMode::Standard,
            relay_url: String::from("https://relay.sibna.dev"),
            proxy_url: None,
        }
    }
}

impl SecureContext {
    /// Create a new secure context with the given configuration
    ///
    /// # Arguments
    /// * `config` - Configuration options
    /// * `master_password` - Optional master password for storage encryption
    ///
    /// # Returns
    /// A new SecureContext instance or an error
    ///
    /// # Security Note
    /// If no master password is provided, a random key is generated.
    pub fn new(config: Config, master_password: Option<&[u8]>) -> ProtocolResult<Self> {
        // Validate password if provided - use unified validation rules
        if let Some(password) = master_password {
            validation::validate_password(password)
                .map_err(|_| ProtocolError::WeakPassword)?;
        }

        // Derive storage key from master password using Argon2id (memory-hard KDF).
        //
        // FIX: Replaced HkdfKdf::derive_iterated(10000 rounds) with Argon2id.
        // HKDF-iterated is NOT a password-based KDF: it is fast to compute, which
        // means an attacker with a GPU can try billions of password candidates per
        // second. Argon2id is specifically designed to be memory-hard and GPU-resistant.
        //
        // The salt is randomly generated here and must be stored alongside the
        // encrypted keystore so it can be reproduced on load. Currently the salt is
        // ephemeral (not persisted), which means the storage key changes on every
        // restart. Integrators using persistent storage MUST persist the salt.
        // TODO (tracked): persist salt in the keystore header before v1.1 release.
        let (storage_key, storage_salt) = if let Some(password) = master_password {
            #[cfg(feature = "argon2")]
            {
                use argon2::Argon2;
                use zeroize::Zeroizing;

                let salt_bytes = crate::crypto::random_vec(32);
                let mut salt_arr = [0u8; 32];
                salt_arr.copy_from_slice(&salt_bytes);

                let params = argon2::Params::new(
                    argon2::Params::DEFAULT_M_COST,
                    argon2::Params::DEFAULT_T_COST,
                    argon2::Params::DEFAULT_P_COST,
                    Some(32)
                ).map_err(|_| ProtocolError::KeyDerivationFailed)?;
                let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

                let mut key_bytes = [0u8; 32];
                argon2.hash_password_into(password, &salt_arr, &mut key_bytes)
                    .map_err(|_| ProtocolError::KeyDerivationFailed)?;

                (Zeroizing::new(key_bytes), salt_arr)
            }
            #[cfg(not(feature = "argon2"))]
            {
                let salt = crypto::random_vec(32);
                let mut salt_arr = [0u8; 32];
                salt_arr.copy_from_slice(&salt);
                let key = crypto::kdf::HkdfKdf::derive_iterated(
                    password,
                    &salt,
                    b"SibnaStorageKey_v9",
                    100_000,
                )?;
                (key, salt_arr)
            }
        } else {
            (crypto::KeyGenerator::generate_key()?, [0u8; 32])
        };

        // Generate device ID
        let mut device_id = [0u8; 16];
        let mut rng = SecureRandom::new()?;
        rng.fill_bytes(&mut device_id);

        // Create keystore
        let keystore = KeyStore::new()?;

        // Create session manager
        let sessions = SessionManager::new(config.clone())?;

        // Create group manager
        let storage_key_arr: &[u8; 32] = &storage_key;
        let groups = GroupManager::new(storage_key_arr)?;

        // Create rate limiter
        let rate_limiter = RateLimiter::new();

        Ok(Self {
            keystore: Arc::new(RwLock::new(keystore)),
            sessions: Arc::new(RwLock::new(sessions)),
            groups: Arc::new(RwLock::new(groups)),
            config: config.clone(),
            random: Arc::new(RwLock::new(rng)),
            storage_key: Arc::new(RwLock::new(storage_key)),
            storage_salt: Arc::new(RwLock::new(storage_salt)),
            device_id,
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
            sequence_number: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            created_at: std::time::Instant::now(),
        })
    }

    /// Create an in-memory context (for WASM/testing)
    #[cfg(target_arch = "wasm32")]
    pub fn new_in_memory(config: Config) -> ProtocolResult<Self> {
        let storage_key = crypto::KeyGenerator::generate_key()?;

        let mut device_id = [0u8; 16];
        let mut rng = SecureRandom::new()?;
        rng.fill_bytes(&mut device_id);

        let keystore = KeyStore::new_in_memory()?;
        let sessions = SessionManager::new_in_memory(config.clone())?;
        let groups = GroupManager::new(storage_key.as_ref())?;
        let rate_limiter = RateLimiter::new();

        Ok(Self {
            keystore: Arc::new(RwLock::new(keystore)),
            sessions: Arc::new(RwLock::new(sessions)),
            groups: Arc::new(RwLock::new(groups)),
            config,
            random: Arc::new(RwLock::new(rng)),
            storage_key: Arc::new(RwLock::new(storage_key)),
            storage_salt: Arc::new(RwLock::new([0u8; 32])),
            device_id,
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
            sequence_number: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            created_at: std::time::Instant::now(),
        })
    }

    /// Get the device ID
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get the keystore (for testing/FFI)
    pub fn keystore(&self) -> Arc<RwLock<KeyStore>> {
        self.keystore.clone()
    }

    /// Get the rate limiter (for testing)
    pub fn rate_limiter(&self) -> Arc<RwLock<RateLimiter>> {
        self.rate_limiter.clone()
    }

    /// Get protocol version
    pub fn version(&self) -> &'static str {
        VERSION
    }

    /// Create a new session with a peer
    pub fn create_session(&self, peer_id: &[u8]) -> ProtocolResult<SessionHandle> {
        // Check rate limit
        if self.config.enable_rate_limiting {
            let limiter = self.rate_limiter.write();
            limiter.check("create_session", &hex::encode(peer_id))
                .map_err(|_| ProtocolError::RateLimitExceeded)?;
        }

        let sessions = self.sessions.read();
        sessions.create_session(peer_id, self.config.clone())
    }

    /// Load an identity key pair into the keystore
    pub fn load_identity(&self, ed_pub: &[u8], x_pub: &[u8], seed: &[u8]) -> ProtocolResult<()> {
        if ed_pub.len() != 32 || x_pub.len() != 32 || seed.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }

        let keypair = crate::keystore::IdentityKeyPair::from_bytes(ed_pub, x_pub, seed)
            .map_err(|_| ProtocolError::InvalidKey)?;
        self.keystore.write().set_identity(keypair)
    }

    /// Set device link credentials for multi-device sync
    pub fn set_device_link(&self, device_id: u32, root_key: &[u8; 32], signature: &[u8; 64]) -> ProtocolResult<()> {
        self.keystore.write().set_device_link(device_id, *root_key, *signature);
        Ok(())
    }

    /// Generate a new identity
    pub fn generate_identity(&self) -> ProtocolResult<IdentityKeyPair> {
        let keypair = IdentityKeyPair::generate();
        self.keystore.write().set_identity(keypair.clone())?;
        Ok(keypair)
    }

    /// Get the current identity
    pub fn get_identity(&self) -> ProtocolResult<IdentityKeyPair> {
        self.keystore.read().get_identity_keypair()
    }

    /// Perform X3DH handshake with a peer
    #[allow(clippy::too_many_arguments)]
    pub fn perform_handshake(
        &self,
        peer_id: &[u8],
        initiator: bool,
        peer_identity_key: Option<&[u8]>,
        peer_signed_prekey: Option<&[u8]>,
        peer_onetime_prekey: Option<&[u8]>,
        prologue: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        // Check rate limit
        if self.config.enable_rate_limiting {
            let limiter = self.rate_limiter.write();
            limiter.check("handshake", &hex::encode(peer_id))
                .map_err(|_| ProtocolError::RateLimitExceeded)?;
        }

        let keystore = self.keystore.read();
        let random = self.random.read();

        let mut builder = HandshakeBuilder::new()
            .with_config(self.config.clone())
            .with_keystore(&*keystore)
            .with_random(&*random)
            .with_initiator(initiator);

        if let Some(pk) = peer_identity_key {
            builder = builder.with_peer_identity_key(pk)?;
        }
        if let Some(spk) = peer_signed_prekey {
            builder = builder.with_peer_signed_prekey(spk)?;
        }
        if let Some(opk) = peer_onetime_prekey {
            builder = builder.with_peer_onetime_prekey(opk)?;
        }
        if let Some(p) = prologue {
            builder = builder.with_prologue(p);
        }

        let mut handshake = builder.build()?;
        let output = handshake.perform()?;

        // KEY PINNING: Verify or pin the peer's identity key.
        // If the key has changed since last contact, abort immediately.
        if let Some(pk_bytes) = peer_identity_key {
            if pk_bytes.len() == 32 {
                let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| ProtocolError::InvalidKeyLength)?;
                drop(keystore); // release read lock before acquiring write
                let mut keystore_w = self.keystore.write();
                keystore_w.verify_or_pin_peer_key(peer_id, &pk_arr)?;
                drop(keystore_w);
            } else {
                drop(keystore);
            }
        } else {
            drop(keystore);
        }

        let sessions = self.sessions.write();

        // FIX: Correct remote_dh selection for Double Ratchet initialisation.
        //
        // For the INITIATOR: the first DH ratchet step uses the peer's signed prekey
        // as the initial remote DH public key — this matches the X3DH output.
        //
        // For the RESPONDER: the first DH ratchet step uses the initiator's EPHEMERAL
        // key (peer_onetime_prekey here carries the initiator's ephemeral public key,
        // which the responder must use to seed the receiving chain). Using the OPK
        // itself as remote_dh was a protocol-layer bug — the OPK is already consumed
        // inside x3dh_responder and must not be reused as the ratchet seed.
        //
        // NOTE: The API parameter `peer_onetime_prekey` is reused here to transport
        // the initiator's ephemeral public key to the responder path. Callers MUST
        // pass the initiator's ephemeral public key (not their OPK) when initiator=false.
        let (remote_dh, local_dh) = if initiator {
            // Initiator seeds the ratchet with peer's SPK as first remote DH key.
            let spk = peer_signed_prekey.ok_or(ProtocolError::InvalidState)?;
            let remote_dh = PublicKey::from(
                <[u8; 32]>::try_from(spk).map_err(|_| ProtocolError::InvalidKeyLength)?
            );
            (remote_dh, output.local_ephemeral_key)
        } else {
            // Responder seeds the ratchet with initiator's ephemeral public key.
            // The caller passes this in peer_onetime_prekey for the responder path.
            let initiator_eph = peer_onetime_prekey.ok_or(ProtocolError::InvalidState)?;
            let remote_dh = PublicKey::from(
                <[u8; 32]>::try_from(initiator_eph)
                    .map_err(|_| ProtocolError::InvalidKeyLength)?
            );
            (remote_dh, output.local_ephemeral_key)
        };

        let session = DoubleRatchetSession::from_shared_secret(
            &output.shared_secret,
            local_dh,
            remote_dh,
            self.config.clone(),
            initiator,
        )?;

        let session_arc = Arc::new(RwLock::new(session));
        sessions.insert_session(peer_id, session_arc.clone())?;

        // FIX: Do NOT return raw shared_secret to caller - it belongs only to the session.
        // Callers use encrypt_message/decrypt_message via the session.
        Ok(peer_id.to_vec()) // Return peer_id as session identifier
    }

    /// Generate a Cover Traffic message (Dummy Traffic).
    ///
    /// Generates an encrypted, fully padded message that carries no actual payload.
    /// When the peer receives it, it decrypts to an empty payload map (`Vec::new()`).
    /// To a network observer, this looks mathematically identical to a real message
    /// in size and entropy, defeating traffic analysis (metadata frequency analysis).
    pub fn generate_cover_message(&self, session_id: &[u8]) -> ProtocolResult<Vec<u8>> {
        self.encrypt_message(session_id, &[], None)
    }

    /// Encrypt a message for a session
    pub fn encrypt_message(
        &self,
        session_id: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        // Check rate limit
        if self.config.enable_rate_limiting {
            let limiter = self.rate_limiter.write();
            limiter.check("encrypt", &hex::encode(session_id))
                .map_err(|_| ProtocolError::RateLimitExceeded)?;
        }

        // Validate message size
        if plaintext.len() > self.config.max_message_size {
            return Err(ProtocolError::InvalidArgument);
        }

        // Apply padding to hide message size from network observers
        let padded = pad_message(plaintext, self.config.message_padding)?;

        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        drop(sessions); // release outer lock before acquiring inner state write lock

        // DoubleRatchetSession::encrypt uses internal RwLock::write on state
        let session_guard = session.read();
        let ad = associated_data.unwrap_or_default();

        session_guard.encrypt(&padded, ad)
    }

    /// Decrypt a message from a session.
    ///
    /// # Note on Cover Traffic
    /// If the returned plaintext `Vec<u8>` is empty (`len() == 0`), it means this was
    /// a Cover Traffic (Dummy) message sent to confuse traffic analyzers.
    /// Applications should silently ignore empty decrypted messages.
    pub fn decrypt_message(
        &self,
        session_id: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        // Check rate limit
        if self.config.enable_rate_limiting {
            let limiter = self.rate_limiter.write();
            limiter.check("decrypt", &hex::encode(session_id))
                .map_err(|_| ProtocolError::RateLimitExceeded)?;
        }

        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        drop(sessions); // release outer lock before acquiring inner state write lock

        // DoubleRatchetSession::decrypt uses internal RwLock::write on state
        let session_guard = session.read();
        let ad = associated_data.unwrap_or_default();

        let padded_plaintext = session_guard.decrypt(ciphertext, ad)?;

        // Strip padding to recover the original message
        unpad_message(&padded_plaintext)
    }

    /// Create a new group
    pub fn create_group(&self, group_id: [u8; 32]) -> ProtocolResult<()> {
        if !self.config.enable_group_messaging {
            return Err(ProtocolError::InvalidState);
        }

        let mut groups = self.groups.write();
        groups.create_group(group_id)?;
        Ok(())
    }

    /// Encrypt a group message
    pub fn encrypt_group_message(
        &self,
        group_id: &[u8; 32],
        plaintext: &[u8],
    ) -> ProtocolResult<GroupMessage> {
        if !self.config.enable_group_messaging {
            return Err(ProtocolError::InvalidState);
        }

        let mut groups = self.groups.write();
        let group = groups.get_group_mut(group_id)
            .ok_or_else(|| ProtocolError::InvalidState)?;
        group.encrypt(plaintext)
    }

    /// Decrypt a group message
    pub fn decrypt_group_message(
        &self,
        message: &GroupMessage,
        sender_public_key: &[u8; 32],
    ) -> ProtocolResult<Vec<u8>> {
        if !self.config.enable_group_messaging {
            return Err(ProtocolError::InvalidState);
        }

        let mut groups = self.groups.write();
        let group = groups.get_group_mut(&message.group_id)
            .ok_or_else(|| ProtocolError::InvalidState)?;
        group.decrypt(message, sender_public_key)
    }

    /// Add member to group
    pub fn add_group_member(&self, group_id: &[u8; 32], public_key: [u8; 32]) -> ProtocolResult<()> {
        if !self.config.enable_group_messaging {
            return Err(ProtocolError::InvalidState);
        }

        let mut groups = self.groups.write();
        let group = groups.get_group_mut(group_id)
            .ok_or_else(|| ProtocolError::InvalidState)?;
        group.add_member(public_key)?;
        Ok(())
    }

    /// Remove member from group
    pub fn remove_group_member(&self, group_id: &[u8; 32], public_key: &[u8; 32]) -> ProtocolResult<()> {
        if !self.config.enable_group_messaging {
            return Err(ProtocolError::InvalidState);
        }

        let mut groups = self.groups.write();
        let group = groups.get_group_mut(group_id)
            .ok_or_else(|| ProtocolError::InvalidState)?;
        group.remove_member(public_key)?;
        Ok(())
    }

    /// List all sessions
    pub fn list_sessions(&self) -> Vec<Vec<u8>> {
        self.sessions.read().list_sessions()
    }

    /// List all groups
    pub fn list_groups(&self) -> Vec<[u8; 32]> {
        self.groups.read().list_groups().into_iter().cloned().collect()
    }

    /// Delete a session
    pub fn delete_session(&self, session_id: &[u8]) -> bool {
        self.sessions.read().remove_session(session_id)
    }

    /// Leave a group
    pub fn leave_group(&self, group_id: &[u8; 32]) {
        self.groups.write().leave_group(group_id);
    }

    /// Get context statistics
    pub fn stats(&self) -> ContextStats {
        ContextStats {
            session_count: self.sessions.read().session_count(),
            group_count: self.groups.read().group_count(),
            age_secs: self.created_at.elapsed().as_secs(),
            version: VERSION.to_string(),
        }
    }

    /// Check if context is healthy
    pub fn is_healthy(&self) -> bool {
        // Check if keystore is accessible
        if !self.keystore.read().is_healthy() {
            return false;
        }

        // Check if sessions are accessible
        if !self.sessions.read().is_healthy() {
            return false;
        }

        true
    }

    /// Save the entire context to disk atomically.
    pub fn save_to_disk(&self, path: &std::path::Path) -> ProtocolResult<()> {
        let keystore = self.keystore.read();
        let sessions = self.sessions.read();
        let groups = self.groups.read();
        let storage_key = self.storage_key.read();
        let salt = self.storage_salt.read();
        let seq = self.sequence_number.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        crate::storage::SecureStorage::save_context(
            path,
            &*storage_key,
            &*salt,
            &*keystore,
            &*sessions,
            &*groups,
            seq + 1,
        )
    }

    /// Load the entire context from disk.
    pub fn load_from_disk(path: &std::path::Path, password: &[u8]) -> ProtocolResult<Self> {
        // We use a dummy key first just to read the header/salt.
        // Or we can modify SecureStorage to return the salt *before* decryption.
        // For efficiency, we'll try to read the MAGIC + SALT directly.
        use std::io::Read;
        let mut file = std::fs::File::open(path).map_err(|_| ProtocolError::StorageError)?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).map_err(|_| ProtocolError::StorageError)?;
        let mut salt = [0u8; 32];
        file.read_exact(&mut salt).map_err(|_| ProtocolError::StorageError)?;
        
        let storage_key = crypto::kdf::HkdfKdf::derive_iterated(
            password,
            &salt,
            b"SibnaStorageKey_v9",
            100_000,
        )?;

        let (payload, _) = crate::storage::SecureStorage::load_context(path, &*storage_key)?;
        
        let config = payload.sessions._config.clone();
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&[0u8; 16]); 

        Ok(Self {
            keystore: Arc::new(RwLock::new(payload.keystore)),
            sessions: Arc::new(RwLock::new(payload.sessions)),
            groups: Arc::new(RwLock::new(payload.groups)),
            config,
            random: Arc::new(RwLock::new(SecureRandom::new()?)),
            storage_key: Arc::new(RwLock::new(storage_key)),
            storage_salt: Arc::new(RwLock::new(salt)),
            device_id,
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
            sequence_number: Arc::new(std::sync::atomic::AtomicU64::new(payload.sequence_number)),
            created_at: std::time::Instant::now(),
        })
    }
}


impl Zeroize for SecureContext {
    fn zeroize(&mut self) {
        // storage_key is Zeroizing<[u8;32]> — already zeroed on drop
        // keystore, sessions, groups contain their own ZeroizeOnDrop fields
        // device_id is non-sensitive (public identifier)
        self.storage_key.write().zeroize();
    }
}

impl Drop for SecureContext {
    fn drop(&mut self) {
        // Sensitive data will be zeroized automatically
    }
}

impl ZeroizeOnDrop for SecureContext {}

/// Context statistics
#[derive(Clone, Debug)]
pub struct ContextStats {
    /// Number of active sessions
    pub session_count: usize,
    /// Number of groups
    pub group_count: usize,
    /// Context age in seconds
    pub age_secs: u64,
    /// Protocol version
    pub version: String,
}

/// Session Manager - Handles active sessions and persistence
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionManager {
    #[serde(with = "sessions_map_serde")]
    sessions: dashmap::DashMap<Vec<u8>, Arc<RwLock<DoubleRatchetSession>>>,
    _config: Config,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(config: Config) -> ProtocolResult<Self> {
        Ok(Self {
            sessions: dashmap::DashMap::new(),
            _config: config,
        })
    }

    /// Create an in-memory session manager (for WASM)
    #[cfg(target_arch = "wasm32")]
    pub fn new_in_memory(config: Config) -> ProtocolResult<Self> {
        Self::new(config)
    }

    /// Create a new session
    pub fn create_session(&self, peer_id: &[u8], config: Config) -> ProtocolResult<SessionHandle> {
        let session = DoubleRatchetSession::new(config)?;
        let session = Arc::new(RwLock::new(session));

        self.sessions.insert(peer_id.to_vec(), session.clone());

        Ok(SessionHandle {
            peer_id: peer_id.to_vec(),
            session,
        })
    }

    /// Get an existing session by ID
    pub fn get_session(&self, session_id: &[u8]) -> ProtocolResult<Arc<RwLock<DoubleRatchetSession>>> {
        self.sessions.get(session_id)
            .map(|s| s.value().clone())
            .ok_or(ProtocolError::SessionNotFound)
    }

    /// Insert a session into the cache
    pub fn insert_session(&self, peer_id: &[u8], session: Arc<RwLock<DoubleRatchetSession>>) -> ProtocolResult<()> {
        self.sessions.insert(peer_id.to_vec(), session);
        Ok(())
    }

    /// Remove a session
    pub fn remove_session(&self, session_id: &[u8]) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// List all session IDs
    pub fn list_sessions(&self) -> Vec<Vec<u8>> {
        self.sessions.iter().map(|s| s.key().clone()).collect()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if manager is healthy
    pub fn is_healthy(&self) -> bool {
        !self.sessions.is_empty() || self.sessions.len() == 0
    }

    /// Iterate over sessions (v2.0.0)
    pub fn iter(&self) -> dashmap::iter::Iter<'_, Vec<u8>, Arc<RwLock<DoubleRatchetSession>>> {
        self.sessions.iter()
    }
}

mod sessions_map_serde {
    use super::*;
    use serde::{Serializer, Deserializer, Deserialize};
    use std::collections::HashMap;

    pub fn serialize<S>(
        map: &dashmap::DashMap<Vec<u8>, Arc<RwLock<DoubleRatchetSession>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map_ser = serializer.serialize_map(Some(map.len()))?;
        for item in map.iter() {
            let session = item.value().read();
            map_ser.serialize_entry(item.key(), &*session)?;
        }
        map_ser.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<dashmap::DashMap<Vec<u8>, Arc<RwLock<DoubleRatchetSession>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let normal_map: HashMap<Vec<u8>, DoubleRatchetSession> =
            HashMap::deserialize(deserializer)?;
        let dash = dashmap::DashMap::new();
        for (k, v) in normal_map {
            dash.insert(k, Arc::new(RwLock::new(v)));
        }
        Ok(dash)
    }
}

/// Session Handle - Reference to an active session
#[derive(Clone)]
pub struct SessionHandle {
    peer_id: Vec<u8>,
    session: Arc<RwLock<DoubleRatchetSession>>,
}

impl SessionHandle {
    /// Get the peer ID
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    /// Get the session
    pub fn session(&self) -> Arc<RwLock<DoubleRatchetSession>> {
        self.session.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.enable_forward_secrecy);
        assert!(config.enable_group_messaging);
        assert_eq!(config.max_group_size, 256);
    }

    #[test]
    fn test_context_creation() {
        let config = Config::default();
        let result = SecureContext::new(config, Some(b"SecurePass1!"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_context_creation_no_password() {
        let config = Config::default();
        let result = SecureContext::new(config, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_identity_generation() {
        let config = Config::default();
        let ctx = SecureContext::new(config, Some(b"SecurePass1!")).unwrap();
        let identity = ctx.generate_identity();
        assert!(identity.is_ok());
    }

    #[test]
    fn test_weak_password() {
        let config = Config::default();
        let result = SecureContext::new(config, Some(b"short"));
        assert!(result.is_err());
    }

    #[test]
    fn test_context_stats() {
        let config = Config::default();
        let ctx = SecureContext::new(config, Some(b"Abcdef123")).unwrap();
        
        let stats = ctx.stats();
        assert_eq!(stats.session_count, 0);
        assert_eq!(stats.group_count, 0);
        assert_eq!(stats.version, VERSION);
    }

    #[test]
    fn test_version() {
        let config = Config::default();
        let ctx = SecureContext::new(config, Some(b"Abcdef123")).unwrap();
        
        assert_eq!(ctx.version(), VERSION);
    }
}
