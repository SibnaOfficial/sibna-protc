#![allow(missing_docs)]
//! Handshake Builder
//!
//! Builder pattern for constructing X3DH handshakes.

use super::{HandshakeOutput, HandshakeRole, HandshakeError};
use crate::error::{ProtocolError, ProtocolResult};
use crate::keystore::KeyStore;
use crate::crypto::SecureRandom;
use crate::Config;
use x25519_dalek::{StaticSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Handshake Builder
///
/// Constructs X3DH handshakes with proper validation and security checks.
pub struct HandshakeBuilder {
    /// Configuration
    config: Config,
    /// Keystore for accessing keys
    keystore: Option<KeyStore>,
    /// Random number generator
    random: Option<SecureRandom>,
    /// Handshake role
    role: Option<HandshakeRole>,
    /// Peer identity key
    peer_identity_key: Option<[u8; 32]>,
    /// Peer signed prekey
    peer_signed_prekey: Option<[u8; 32]>,
    /// Peer one-time prekey
    peer_onetime_prekey: Option<[u8; 32]>,
    /// Peer ephemeral key (for responder)
    peer_ephemeral_key: Option<[u8; 32]>,
    /// Our one-time prekey ID (for responder)
    our_onetime_prekey_id: Option<u32>,
    /// Peer PQ Public Key (for initiator)
    #[cfg(feature = "pqc")]
    peer_pq_pk: Option<Vec<u8>>,
    /// Our PQ Secret Key (for responder)
    #[cfg(feature = "pqc")]
    our_pq_sk: Option<Vec<u8>>,
    /// Peer PQ Ciphertext (for responder)
    #[cfg(feature = "pqc")]
    peer_pq_ct: Option<Vec<u8>>,
    /// Prologue data
    prologue: Option<Vec<u8>>,
    /// Associated data
    associated_data: Option<Vec<u8>>,
}

impl HandshakeBuilder {
    /// Create a new handshake builder
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            keystore: None,
            random: None,
            role: None,
            peer_identity_key: None,
            peer_signed_prekey: None,
            peer_onetime_prekey: None,
            peer_ephemeral_key: None,
            our_onetime_prekey_id: None,
            #[cfg(feature = "pqc")]
            peer_pq_pk: None,
            #[cfg(feature = "pqc")]
            our_pq_sk: None,
            #[cfg(feature = "pqc")]
            peer_pq_ct: None,
            prologue: None,
            associated_data: None,
        }
    }

    /// Set configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Set keystore
    pub fn with_keystore(mut self, keystore: &KeyStore) -> Self {
        self.keystore = Some(keystore.clone());
        self
    }

    /// Set random number generator
    pub fn with_random(mut self, random: &SecureRandom) -> Self {
        self.random = Some(random.clone());
        self
    }

    /// Set handshake role
    pub fn with_role(mut self, role: HandshakeRole) -> Self {
        self.role = Some(role);
        self
    }

    /// Set as initiator
    pub fn with_initiator(mut self, initiator: bool) -> Self {
        self.role = Some(if initiator {
            HandshakeRole::Initiator
        } else {
            HandshakeRole::Responder
        });
        self
    }

    /// Set peer identity key
    pub fn with_peer_identity_key(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        self.peer_identity_key = Some(arr);
        Ok(self)
    }

    /// Set peer signed prekey
    pub fn with_peer_signed_prekey(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        self.peer_signed_prekey = Some(arr);
        Ok(self)
    }

    /// Set peer one-time prekey
    pub fn with_peer_onetime_prekey(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        self.peer_onetime_prekey = Some(arr);
        Ok(self)
    }

    /// Set peer ephemeral key
    pub fn with_peer_ephemeral_key(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        self.peer_ephemeral_key = Some(arr);
        Ok(self)
    }

    /// Set our one-time prekey ID
    pub fn with_our_onetime_prekey_id(mut self, id: u32) -> Self {
        self.our_onetime_prekey_id = Some(id);
        self
    }

    /// Set peer PQ public key
    #[cfg(feature = "pqc")]
    pub fn with_peer_pq_pk(mut self, pk: &[u8]) -> ProtocolResult<Self> {
        if pk.len() != 1184 {
            return Err(ProtocolError::InvalidKeyLength);
        }
        self.peer_pq_pk = Some(pk.to_vec());
        Ok(self)
    }

    /// Set our PQ secret key
    #[cfg(feature = "pqc")]
    pub fn with_our_pq_sk(mut self, sk: &[u8]) -> ProtocolResult<Self> {
        if sk.len() != 2400 {
            return Err(ProtocolError::InvalidKeyLength);
        }
        self.our_pq_sk = Some(sk.to_vec());
        Ok(self)
    }

    /// Set peer PQ ciphertext
    #[cfg(feature = "pqc")]
    pub fn with_peer_pq_ct(mut self, ct: &[u8]) -> ProtocolResult<Self> {
        if ct.len() != 1088 {
            return Err(ProtocolError::InvalidKeyLength);
        }
        self.peer_pq_ct = Some(ct.to_vec());
        Ok(self)
    }

    /// Set prologue data
    pub fn with_prologue(mut self, prologue: &[u8]) -> Self {
        self.prologue = Some(prologue.to_vec());
        self
    }

    /// Set associated data
    pub fn with_associated_data(mut self, ad: &[u8]) -> Self {
        self.associated_data = Some(ad.to_vec());
        self
    }

    /// Build the handshake
    pub fn build(self) -> ProtocolResult<X3dhHandshake> {
        // Validate required fields
        let role = self.role.ok_or(ProtocolError::InvalidState)?;
        let keystore = self.keystore.ok_or(ProtocolError::InvalidState)?;
        
        Ok(X3dhHandshake {
            _config: self.config,
            keystore,
            random: match self.random {
                Some(r) => r,
                None => SecureRandom::new().map_err(|_| HandshakeError::InvalidState)?,
            },
            role,
            peer_identity_key: self.peer_identity_key,
            peer_signed_prekey: self.peer_signed_prekey,
            peer_onetime_prekey: self.peer_onetime_prekey,
            peer_ephemeral_key: self.peer_ephemeral_key,
            our_onetime_prekey_id: self.our_onetime_prekey_id,
            #[cfg(feature = "pqc")]
            peer_pq_pk: self.peer_pq_pk,
            #[cfg(feature = "pqc")]
            our_pq_sk: self.our_pq_sk,
            #[cfg(feature = "pqc")]
            peer_pq_ct: self.peer_pq_ct,
            prologue: self.prologue,
            associated_data: self.associated_data,
        })
    }
}

impl Default for HandshakeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// X3DH Handshake implementation
pub struct X3dhHandshake {
    /// Configuration
    _config: Config,
    /// Keystore
    keystore: KeyStore,
    /// Random number generator
    random: SecureRandom,
    /// Handshake role
    role: HandshakeRole,
    /// Peer identity key
    peer_identity_key: Option<[u8; 32]>,
    /// Peer signed prekey
    peer_signed_prekey: Option<[u8; 32]>,
    /// Peer one-time prekey
    peer_onetime_prekey: Option<[u8; 32]>,
    /// Peer ephemeral key
    peer_ephemeral_key: Option<[u8; 32]>,
    /// Our one-time prekey ID
    our_onetime_prekey_id: Option<u32>,
    /// Peer PQ Public Key
    #[cfg(feature = "pqc")]
    peer_pq_pk: Option<Vec<u8>>,
    /// Our PQ Secret Key
    #[cfg(feature = "pqc")]
    our_pq_sk: Option<Vec<u8>>,
    /// Peer PQ Ciphertext
    #[cfg(feature = "pqc")]
    peer_pq_ct: Option<Vec<u8>>,
    /// Prologue data
    prologue: Option<Vec<u8>>,
    /// Associated data
    associated_data: Option<Vec<u8>>,
}

impl X3dhHandshake {
    /// Perform the handshake
    pub fn perform(&mut self) -> ProtocolResult<HandshakeOutput> {
        match self.role {
            HandshakeRole::Initiator => self.perform_initiator(),
            HandshakeRole::Responder => self.perform_responder(),
        }
    }

    /// Perform initiator handshake
    fn perform_initiator(&mut self) -> ProtocolResult<HandshakeOutput> {
        use crate::handshake::x3dh::x3dh_initiator_v10;

        // Get our identity key
        let our_identity = self.keystore.get_identity_keypair()?;

        // Get peer public keys
        let peer_ik = self.peer_identity_key.ok_or(ProtocolError::InvalidState)?;
        let peer_spk = self.peer_signed_prekey.ok_or(ProtocolError::InvalidState)?;
        let peer_opk = self.peer_onetime_prekey;

        // Convert byte keys to PublicKey
        let peer_ik_pub = PublicKey::from(peer_ik);
        let peer_spk_pub = PublicKey::from(peer_spk);
        let peer_opk_pub = peer_opk.map(PublicKey::from);

        // Generate ephemeral key
        let ephemeral_secret = StaticSecret::random_from_rng(&mut self.random);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform X3DH initiator
        let mut x3dh_result = x3dh_initiator_v10(
            our_identity.x25519_secret.as_ref().ok_or(ProtocolError::KeyNotFound)?,
            &ephemeral_secret,
            &peer_ik_pub,
            &peer_spk_pub,
            peer_opk_pub.as_ref(),
            #[cfg(feature = "pqc")]
            self.peer_pq_pk.as_ref(),
            &[0u8; 32], // Default transcript hash for non-P2P flow
        )?;

        // Build associated data
        let ad = self.build_associated_data(&our_identity.x25519_public, &peer_ik);

        let mut output = HandshakeOutput::new(
            x3dh_result.shared_secret,
            ephemeral_secret,
            ephemeral_public,
        ).with_associated_data(ad);

        #[cfg(feature = "pqc")]
        if let Some(ct) = x3dh_result.pq_ciphertext.take() {
            output = output.with_pq_ciphertext(ct);
        }

        output.validate()?;

        Ok(output)
    }

    /// Perform responder handshake
    fn perform_responder(&mut self) -> ProtocolResult<HandshakeOutput> {
        use crate::handshake::x3dh::x3dh_responder_v10;

        // Get our keys
        let our_identity = self.keystore.get_identity_keypair()?;
        let our_signed_prekey = self.keystore.get_signed_prekey()?;
        
        // Get peer public keys
        let peer_ik = self.peer_identity_key.ok_or(ProtocolError::InvalidState)?;
        let peer_ek = self.peer_ephemeral_key.ok_or(ProtocolError::InvalidState)?;

        // Convert byte keys to PublicKey
        let peer_ik_pub = PublicKey::from(peer_ik);
        let peer_ek_pub = PublicKey::from(peer_ek);

        // Get our one-time prekey if ID was specified
        let our_opk = match self.our_onetime_prekey_id {
            Some(id) => Some(self.keystore.get_onetime_prekey_by_id(id)?),
            None => None,
        };

        // Perform X3DH responder
        let x3dh_result = x3dh_responder_v10(
            our_identity.x25519_secret.as_ref().ok_or(ProtocolError::KeyNotFound)?,
            &our_signed_prekey,
            our_opk.as_ref(),
            &peer_ik_pub,
            &peer_ek_pub,
            #[cfg(feature = "pqc")]
            self.our_pq_sk.as_ref(),
            #[cfg(feature = "pqc")]
            self.peer_pq_ct.as_ref(),
            &[0u8; 32], // Default transcript hash for non-P2P flow
        )?;

        // Build associated data
        let ad = self.build_associated_data(&our_identity.x25519_public, &peer_ik);

        // NOTE: In the standard X3DH responder flow, the responder does NOT generate
        // a new ephemeral key — it uses its long-term signed prekey (SPK) for DH.
        // HandshakeOutput::new requires a "local_ephemeral_key" parameter, which we
        // populate with the SPK here. This is architecturally correct for X3DH:
        // the SPK plays the role of a "semi-ephemeral" key (rotated periodically).
        //
        // SECURITY NOTE: The signed prekey is NOT forward-secret in the same way as
        // a truly ephemeral key, because it is reused until explicitly rotated.
        // Callers must rotate the signed prekey regularly (recommended: every 7 days,
        // enforced by SignedPreKey::is_expired). The one-time prekey (OPK), when
        // available, provides additional forward secrecy for the responder.
        let output = HandshakeOutput::new(
            x3dh_result.shared_secret,
            our_signed_prekey.clone(), // SPK acts as semi-ephemeral key (see note above)
            PublicKey::from(&our_signed_prekey),
        ).with_associated_data(ad);

        output.validate()?;

        Ok(output)
    }

    /// Build associated data for session binding
    fn build_associated_data(&self, our_key: &[u8; 32], peer_key: &[u8; 32]) -> Vec<u8> {
        let mut ad = Vec::with_capacity(64 + self.prologue.as_ref().map(|p| p.len()).unwrap_or(0));
        
        // Add identity keys
        ad.extend_from_slice(our_key);
        ad.extend_from_slice(peer_key);
        
        // Add prologue if present
        if let Some(ref prologue) = self.prologue {
            ad.extend_from_slice(prologue);
        }
        
        ad
    }
}

impl Zeroize for X3dhHandshake {
    fn zeroize(&mut self) {
        if let Some(ref mut key) = self.peer_identity_key {
            key.zeroize();
        }
        if let Some(ref mut key) = self.peer_signed_prekey {
            key.zeroize();
        }
        if let Some(ref mut key) = self.peer_onetime_prekey {
            key.zeroize();
        }
        if let Some(ref mut prologue) = self.prologue {
            prologue.zeroize();
        }
        if let Some(ref mut ad) = self.associated_data {
            ad.zeroize();
        }
    }
}

impl ZeroizeOnDrop for X3dhHandshake {}

impl Drop for X3dhHandshake {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = HandshakeBuilder::new();
        assert!(builder.role.is_none());
    }

    #[test]
    fn test_builder_with_role() {
        let builder = HandshakeBuilder::new()
            .with_role(HandshakeRole::Initiator);
        
        assert_eq!(builder.role, Some(HandshakeRole::Initiator));
    }

    #[test]
    fn test_builder_with_initiator() {
        let builder = HandshakeBuilder::new()
            .with_initiator(true);
        
        assert_eq!(builder.role, Some(HandshakeRole::Initiator));
    }

    #[test]
    fn test_builder_with_keys() {
        let builder = HandshakeBuilder::new()
            .with_peer_identity_key(&[0x42u8; 32]).unwrap()
            .with_peer_signed_prekey(&[0x24u8; 32]).unwrap()
            .with_peer_onetime_prekey(&[0xABu8; 32]).unwrap();

        assert!(builder.peer_identity_key.is_some());
        assert!(builder.peer_signed_prekey.is_some());
        assert!(builder.peer_onetime_prekey.is_some());
    }

    #[test]
    fn test_builder_invalid_key_length() {
        let result = HandshakeBuilder::new()
            .with_peer_identity_key(&[0x42u8; 16]);
        
        assert!(result.is_err());
    }
}
