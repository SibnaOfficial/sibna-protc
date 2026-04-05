//! Secure Key Storage
//!
//! Provides secure storage and management of cryptographic keys.
//! All keys are encrypted at rest and zeroized when dropped.

use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::{CryptoHandler, constant_time_eq, constant_time_is_zero};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::crypto::serde_helpers::dh_local_serde;

/// Identity key pair (Ed25519 for signing, X25519 for DH)
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    /// Ed25519 secret key
    pub ed25519_secret: Option<[u8; 32]>,
    /// Ed25519 public key
    pub ed25519_public: [u8; 32],
    /// X25519 secret key
    #[serde(with = "dh_local_serde")]
    pub x25519_secret: Option<x25519_dalek::StaticSecret>,
    /// X25519 public key
    pub x25519_public: [u8; 32],
    /// Key creation timestamp
    pub created_at: u64,
}

impl IdentityKeyPair {
    /// Generate a new identity key pair
    pub fn generate() -> Self {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        // Generate Ed25519 key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_public = signing_key.verifying_key().to_bytes();

        // Generate X25519 key pair
        let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            ed25519_secret: Some(signing_key.to_bytes()),
            ed25519_public,
            x25519_secret: Some(x25519_secret),
            x25519_public: x25519_public.to_bytes(),
            created_at,
        }
    }

    /// Create from bytes
    /// Restore identity key pair from a master seed using HKDF domain separation.
    ///
    /// # Security
    /// Ed25519 and X25519 keys are derived via HKDF with distinct info strings so
    /// that knowing one key does NOT allow derivation of the other. Previously both
    /// were derived directly from the same seed bytes — a cryptographic domain
    /// separation failure that has been corrected here.
    pub fn from_bytes(ed_pub: &[u8], x_pub: &[u8], seed: &[u8]) -> ProtocolResult<Self> {
        use ed25519_dalek::SigningKey;
        use hkdf::Hkdf;
        use sha2::Sha256;
        use zeroize::Zeroize;
        use crate::error::ProtocolError;

        let ed25519_public: [u8; 32] = ed_pub
            .try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;
        let x25519_public: [u8; 32] = x_pub
            .try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;
        let seed_arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;

        // FIX: Use HKDF with distinct info tags to derive separate key material
        // for Ed25519 and X25519. Reusing the raw seed for both leaks cross-domain
        // key material and violates cryptographic separation.
        let hkdf = Hkdf::<Sha256>::new(None, &seed_arr);
        let mut ed_seed = [0u8; 32];
        let mut x_seed = [0u8; 32];
        hkdf.expand(b"SibnaIdentityKey_Ed25519_v1", &mut ed_seed)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
        hkdf.expand(b"SibnaIdentityKey_X25519_v1", &mut x_seed)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        let signing_key = SigningKey::from_bytes(&ed_seed);
        let x25519_secret = x25519_dalek::StaticSecret::from(x_seed);
        ed_seed.zeroize();
        x_seed.zeroize();

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            ed25519_secret: Some(signing_key.to_bytes()),
            ed25519_public,
            x25519_secret: Some(x25519_secret),
            x25519_public,
            created_at,
        })
    }

    /// Sign data with Ed25519
    pub fn sign(&self, data: &[u8]) -> ProtocolResult<[u8; 64]> {
        use ed25519_dalek::{Signer, SigningKey};

        let secret = self.ed25519_secret
            .ok_or(ProtocolError::InvalidState)?;

        let signing_key = SigningKey::from_bytes(&secret);
        let signature = signing_key.sign(data);

        Ok(signature.to_bytes())
    }

    /// Verify signature with Ed25519
    pub fn verify(&self, data: &[u8], signature: &[u8; 64]) -> ProtocolResult<bool> {
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};

        let verifying_key = VerifyingKey::from_bytes(&self.ed25519_public)
            .map_err(|_| ProtocolError::InvalidKey)?;

        let sig = Signature::from_bytes(signature);

        match verifying_key.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get key fingerprint
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(&self.ed25519_public);
        hasher.update(&self.x25519_public);
        hasher.finalize().into()
    }

    /// Check if keys are valid
    pub fn is_valid(&self) -> bool {
        // Check public keys are not all zeros
        if constant_time_is_zero(&self.ed25519_public) {
            return false;
        }
        if constant_time_is_zero(&self.x25519_public) {
            return false;
        }

        // Check derived public key matches
        if let Some(ref x_secret) = self.x25519_secret {
            let derived_public = x25519_dalek::PublicKey::from(x_secret);
            constant_time_eq(derived_public.as_bytes(), &self.x25519_public)
        } else {
            false
        }
    }
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("ed25519_public", &self.ed25519_public)
            .field("x25519_public", &self.x25519_public)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Zeroize for IdentityKeyPair {
    fn zeroize(&mut self) {
        if let Some(ref mut secret) = self.ed25519_secret {
            secret.zeroize();
        }
        self.ed25519_public.zeroize();
        // x25519_secret will be zeroized by ZeroizeOnDrop
        self.x25519_public.zeroize();
    }
}

impl ZeroizeOnDrop for IdentityKeyPair {}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Signed prekey with metadata
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    /// Key ID
    pub key_id: u32,
    /// X25519 secret key
    #[serde(with = "dh_local_serde")]
    pub secret: Option<x25519_dalek::StaticSecret>,
    /// X25519 public key
    pub public: [u8; 32],
    /// Signature by identity key
    pub signature: Vec<u8>,
    /// Post-Quantum secret key (ML-KEM-768)
    #[cfg(feature = "pqc")]
    pub pq_secret: Option<Vec<u8>>,
    /// Post-Quantum public key (ML-KEM-768)
    #[cfg(feature = "pqc")]
    pub pq_public: Option<Vec<u8>>,
    /// Creation timestamp
    pub created_at: u64,
}

impl SignedPreKey {
    /// Generate a new signed prekey
    pub fn generate(key_id: u32, identity: &IdentityKeyPair) -> ProtocolResult<Self> {
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);

        // Sign the public key
        let signature = identity.sign(public.as_bytes())?;

        #[cfg(feature = "pqc")]
        let (pq_public, pq_secret) = {
            use fips203::ml_kem_768;
            use fips203::traits::{KeyGen, SerDes};
            let (pk, sk): (ml_kem_768::EncapsKey, ml_kem_768::DecapsKey) = ml_kem_768::KG::try_keygen()
                .map_err(|_| ProtocolError::InternalErrorDetailed { details: "PQC Keygen failed".to_string() })?;
            (Some(SerDes::into_bytes(pk).to_vec()), Some(SerDes::into_bytes(sk).to_vec()))
        };

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            key_id,
            secret: Some(secret),
            public: public.to_bytes(),
            signature: signature.to_vec(),
            #[cfg(feature = "pqc")]
            pq_secret,
            #[cfg(feature = "pqc")]
            pq_public,
            created_at,
        })
    }

    /// Verify the signature
    pub fn verify(&self, identity: &IdentityKeyPair) -> ProtocolResult<bool> {
        let signature: [u8; 64] = self.signature.as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidSignature)?;
        identity.verify(&self.public, &signature)
    }

    /// Check if key has expired (older than 7 days)
    pub fn is_expired(&self) -> bool {
        let now = crate::crypto::current_timestamp().unwrap_or(self.created_at);
        now > self.created_at + 7 * 86400
    }
}

impl std::fmt::Debug for SignedPreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedPreKey")
            .field("key_id", &self.key_id)
            .field("public", &self.public)
            .field("signature", &self.signature)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Zeroize for SignedPreKey {
    fn zeroize(&mut self) {
        self.public.zeroize();
        self.signature.zeroize();
    }
}

impl ZeroizeOnDrop for SignedPreKey {}

/// One-time prekey
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    /// Key ID
    pub key_id: u32,
    /// Secret key
    #[serde(skip)]
    pub secret: Option<x25519_dalek::StaticSecret>,
    /// Public key
    pub public: [u8; 32],
    /// Whether the key has been used
    pub used: bool,
    /// Creation timestamp
    pub created_at: u64,
}

impl OneTimePreKey {
    /// Generate a new one-time prekey
    pub fn generate(key_id: u32) -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            key_id,
            secret: Some(secret),
            public: public.to_bytes(),
            used: false,
            created_at,
        }
    }

    /// Mark as used
    pub fn mark_used(&mut self) {
        self.used = true;
        // Clear secret after use
        self.secret = None;
    }

    /// Check if key has expired (older than 30 days)
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > self.created_at + 30 * 86400
    }
}

impl std::fmt::Debug for OneTimePreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimePreKey")
            .field("key_id", &self.key_id)
            .field("public", &self.public)
            .field("used", &self.used)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Zeroize for OneTimePreKey {
    fn zeroize(&mut self) {
        self.public.zeroize();
    }
}

impl ZeroizeOnDrop for OneTimePreKey {}

/// A pinned peer identity key (Trust-On-First-Use)
///
/// Stored permanently in the `KeyStore`. On first contact with a peer,
/// their identity key is pinned. On subsequent contacts, the presented key
/// is compared against the pin. A mismatch triggers `ProtocolError::KeyMismatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinnedKey {
    /// The peer's pinned identity key (Ed25519 or X25519 public key, 32 bytes)
    pub identity_key: [u8; 32],
    /// Unix timestamp when this key was first pinned
    pub pinned_at: u64,
    /// Whether the user has verified this key via Safety Number comparison
    pub verified: bool,
    /// Cached Safety Number fingerprint (SHA-512 truncated to 32 bytes)
    pub safety_number: [u8; 32],
}

impl PinnedKey {
    fn new(identity_key: [u8; 32], our_identity: &[u8; 32]) -> Self {
        use sha2::{Sha512, Digest};
        // Sort keys for consistent Safety Number regardless of who calls it
        let (first, second) = if our_identity < &identity_key {
            (our_identity, &identity_key)
        } else {
            (&identity_key, our_identity)
        };
        let mut hasher = Sha512::new();
        hasher.update(b"SIBNA_SAFETY_NUMBER_V1");
        hasher.update(first);
        hasher.update(second);
        let digest = hasher.finalize();
        let mut safety_number = [0u8; 32];
        safety_number.copy_from_slice(&digest[..32]);

        let pinned_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self { identity_key, pinned_at, verified: false, safety_number }
    }
}

/// Result of a `pin_peer_key` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinResult {
    /// First time seeing this peer — key was pinned (TOFU).
    NewPin,
    /// Key matches the existing pin — peer identity is consistent.
    Consistent,
    /// Key CHANGED from the pinned value — possible MITM attack.
    /// The session must be aborted and the user must re-verify.
    KeyChanged {
        /// The previously pinned (trusted) key.
        pinned_key: [u8; 32],
        /// The new (suspicious) key presented now.
        new_key: [u8; 32],
    },
}

/// Secure key store
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyStore {
    /// Identity key pair
    identity: Option<IdentityKeyPair>,
    /// Signed prekey
    signed_prekey: Option<SignedPreKey>,
    /// One-time prekeys
    onetime_prekeys: HashMap<u32, OneTimePreKey>,
    /// Next one-time prekey ID
    next_onetime_id: u32,
    /// Device ID (0 for master device)
    device_id: u32,
    /// Root identity key (if linked)
    root_identity_key: Option<[u8; 32]>,
    /// Device signature from root key (Vec<u8> to bypass serde 32-byte array limit)
    device_signature: Option<Vec<u8>>,
    /// Pinned peer identity keys (TOFU key pinning for MITM detection)
    peer_pins: HashMap<Vec<u8>, PinnedKey>,
    /// Encryption handler for storage
    #[serde(skip)]
    crypto: Option<CryptoHandler>,
}

impl KeyStore {
    /// Create a new key store
    pub fn new() -> ProtocolResult<Self> {
        Ok(Self {
            identity: None,
            signed_prekey: None,
            onetime_prekeys: HashMap::new(),
            next_onetime_id: 1,
            device_id: 0,
            root_identity_key: None,
            device_signature: None,
            peer_pins: HashMap::new(),
            crypto: None,
        })
    }

    /// Create an in-memory key store (for WASM)
    #[cfg(target_arch = "wasm32")]
    pub fn new_in_memory() -> ProtocolResult<Self> {
        Self::new()
    }

    /// Set identity key pair
    pub fn set_identity(&mut self, identity: IdentityKeyPair) -> ProtocolResult<()> {
        if !identity.is_valid() {
            return Err(ProtocolError::InvalidKey);
        }
        self.identity = Some(identity);
        Ok(())
    }

    /// Set device linking credentials (used when this device is linked to a master device)
    pub fn set_device_link(&mut self, device_id: u32, root_key: [u8; 32], signature: [u8; 64]) {
        self.device_id = device_id;
        self.root_identity_key = Some(root_key);
        self.device_signature = Some(signature.to_vec());
    }

    /// Get identity key pair
    pub fn get_identity_keypair(&self) -> ProtocolResult<IdentityKeyPair> {
        self.identity.clone()
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Generate and set signed prekey
    pub fn generate_signed_prekey(&mut self) -> ProtocolResult<()> {
        let identity = self.get_identity_keypair()?;
        let prekey = SignedPreKey::generate(1, &identity)?;
        self.signed_prekey = Some(prekey);
        Ok(())
    }

    /// Get signed prekey
    pub fn get_signed_prekey(&self) -> ProtocolResult<x25519_dalek::StaticSecret> {
        self.signed_prekey
            .as_ref()
            .and_then(|k| k.secret.clone())
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Get signed prekey public
    pub fn get_signed_prekey_public(&self) -> ProtocolResult<[u8; 32]> {
        self.signed_prekey
            .as_ref()
            .map(|k| k.public)
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Get signed prekey PQ public
    #[cfg(feature = "pqc")]
    pub fn get_signed_prekey_pq_public(&self) -> ProtocolResult<Vec<u8>> {
        self.signed_prekey
            .as_ref()
            .and_then(|k| k.pq_public.clone())
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Get signed prekey PQ secret
    #[cfg(feature = "pqc")]
    pub fn get_signed_prekey_pq_secret(&self) -> ProtocolResult<Vec<u8>> {
        self.signed_prekey
            .as_ref()
            .and_then(|k| k.pq_secret.clone())
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Get the Ed25519 signature covering the signed prekey public key
    pub fn get_signed_prekey_signature(&self) -> ProtocolResult<[u8; 64]> {
        let spk = self.signed_prekey.as_ref().ok_or(ProtocolError::KeyNotFound)?;
        let sig: [u8; 64] = spk.signature.as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidSignature)?;
        Ok(sig)
    }

    /// Get the combined data required to build a PreKey bundle.
    /// 
    /// Returns (identity_public, signed_prekey_public, signed_prekey_signature, onetime_prekey_public).
    pub fn get_prekey_bundle_data(&self) -> ProtocolResult<([u8; 32], [u8; 32], [u8; 64], Option<[u8; 32]>)> {
        let identity = self.get_identity_keypair()?;
        let spk_pub = self.get_signed_prekey_public()?;
        let sig = self.get_signed_prekey_signature()?;
        let opk = self.get_onetime_prekey_public().ok().map(|(_, pub_key)| pub_key);
        Ok((identity.ed25519_public, spk_pub, sig, opk))
    }

    /// Generate a cryptographically bound and signed PreKeyBundle.
    ///
    /// This retrieves the current keys, constructs a `PreKeyBundle`, fully signs it
    /// with the Ed25519 Identity secret key to prevent replay attacks, and returns
    /// the serialized bytes ready for network transmission.
    pub fn generate_prekey_bundle_bytes(&self) -> ProtocolResult<Vec<u8>> {
        let identity = self.get_identity_keypair()?;
        let spk_pub = self.get_signed_prekey_public()?;
        let sig = self.get_signed_prekey_signature()?;
        let opk = self.get_onetime_prekey_public().ok().map(|(_, pub_key)| pub_key);

        let root_key = self.root_identity_key.unwrap_or(identity.ed25519_public);
        let dev_sig = match &self.device_signature {
            Some(s) => {
                let mut arr = [0u8; 64];
                if s.len() == 64 { arr.copy_from_slice(s); }
                arr
            },
            None => {
                // If we are the master device (id=0), we sign our own device linking certificate
                let mut dev_payload = Vec::with_capacity(36);
                dev_payload.extend_from_slice(&identity.ed25519_public);
                dev_payload.extend_from_slice(&self.device_id.to_le_bytes());
                identity.sign(&dev_payload)?
            }
        };

        let mut bundle = crate::handshake::PreKeyBundle::new(
            identity.ed25519_public,
            spk_pub,
            sig,
            opk,
            self.device_id,
            root_key,
            dev_sig,
        );

        #[cfg(feature = "pqc")]
        if let Ok(pq_pk) = self.get_signed_prekey_pq_public() {
            // Sign the PQ prekey
            let pq_sig = identity.sign(&pq_pk)?;
            bundle = bundle.with_pq_prekey(pq_pk, pq_sig);
        }

        bundle.sign_bundle(|data| identity.sign(data))?;

        Ok(bundle.to_bytes())
    }

    /// Generate one-time prekeys
    pub fn generate_onetime_prekeys(&mut self, count: usize) -> ProtocolResult<Vec<u32>> {
        let _identity = self.get_identity_keypair()?;
        let mut ids = Vec::with_capacity(count);

        for _ in 0..count {
            let id = self.next_onetime_id;
            self.next_onetime_id += 1;

            let prekey = OneTimePreKey::generate(id);
            ids.push(id);
            self.onetime_prekeys.insert(id, prekey);
        }

        Ok(ids)
    }

    /// Get one-time prekey
    pub fn get_onetime_prekey(&self) -> ProtocolResult<x25519_dalek::StaticSecret> {
        // Find unused, non-expired key
        for (_, prekey) in &self.onetime_prekeys {
            if !prekey.used && !prekey.is_expired() {
                return prekey.secret.clone()
                    .ok_or(ProtocolError::KeyNotFound);
            }
        }
        Err(ProtocolError::KeyNotFound)
    }

    /// Get specific one-time prekey by ID
    pub fn get_onetime_prekey_by_id(&self, id: u32) -> ProtocolResult<x25519_dalek::StaticSecret> {
        self.onetime_prekeys.get(&id)
            .and_then(|k| k.secret.clone())
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Get one-time prekey public
    pub fn get_onetime_prekey_public(&self) -> ProtocolResult<(u32, [u8; 32])> {
        for (id, prekey) in &self.onetime_prekeys {
            if !prekey.used && !prekey.is_expired() {
                return Ok((*id, prekey.public));
            }
        }
        Err(ProtocolError::KeyNotFound)
    }

    /// Mark one-time prekey as used
    pub fn mark_onetime_used(&mut self, key_id: u32) {
        if let Some(prekey) = self.onetime_prekeys.get_mut(&key_id) {
            prekey.mark_used();
        }
    }

    /// Get remaining one-time prekeys count
    pub fn onetime_prekey_count(&self) -> usize {
        self.onetime_prekeys
            .values()
            .filter(|k| !k.used && !k.is_expired())
            .count()
    }

    /// Prune expired and used keys
    pub fn prune_keys(&mut self) {
        self.onetime_prekeys.retain(|_, k| !k.used && !k.is_expired());

        if self.signed_prekey.as_ref().map(|k| k.is_expired()).unwrap_or(false) {
            self.signed_prekey = None;
        }
    }

    /// Check if store is healthy
    pub fn is_healthy(&self) -> bool {
        // Check if we can access the identity key
        self.identity.is_some()
    }

    /// Get key store statistics
    pub fn stats(&self) -> KeyStoreStats {
        KeyStoreStats {
            has_identity: self.identity.is_some(),
            has_signed_prekey: self.signed_prekey.is_some(),
            onetime_prekey_count: self.onetime_prekey_count(),
            total_onetime_prekeys: self.onetime_prekeys.len(),
        }
    }

    // ----------------------------------------------------------------
    // Persistent Disk Storage (feature = "persistent" or available always)
    // ----------------------------------------------------------------

    /// Serialize and encrypt this keystore to bytes.
    ///
    /// The output is `nonce (12) || ciphertext || auth-tag (16)` using
    /// ChaCha20-Poly1305 with `encryption_key` (32 bytes).
    /// The inner payload is bincode-serialized `KeyStore`.
    pub fn to_encrypted_bytes(&self, encryption_key: &[u8; 32]) -> ProtocolResult<Vec<u8>> {
        use crate::crypto::CryptoHandler;

        // Serialize with bincode
        let plaintext = bincode::serialize(self)
            .map_err(|_| ProtocolError::SerializationError)?;

        // Encrypt with ChaCha20-Poly1305
        let handler = CryptoHandler::new(encryption_key.as_ref())
            .map_err(|_| ProtocolError::InternalError)?;
        handler.encrypt(&plaintext, b"SibnaKeyStore_v10")
            .map_err(|_| ProtocolError::StorageError)
    }

    /// Deserialize and decrypt a keystore from encrypted bytes.
    ///
    /// See `to_encrypted_bytes` for the expected format.
    pub fn from_encrypted_bytes(data: &[u8], encryption_key: &[u8; 32]) -> ProtocolResult<Self> {
        use crate::crypto::CryptoHandler;

        let handler = CryptoHandler::new(encryption_key.as_ref())
            .map_err(|_| ProtocolError::InternalError)?;
        let plaintext = handler.decrypt(data, b"SibnaKeyStore_v10")
            .map_err(|_| ProtocolError::StorageError)?;

        let mut store: KeyStore = bincode::deserialize(&plaintext)
            .map_err(|_| ProtocolError::DeserializationError)?;

        // Restore transient (non-serialized) private key fields from their serialized bytes
        // IdentityKeyPair: ed25519_secret and x25519_secret are #[serde(skip)],
        // so they won't be available. This is intentional — callers must call
        // load_identity() to restore them, or the user must re-import their seed.
        // The public keys are always preserved.

        // Restore signed prekey DH secret from public bytes if secret is missing
        // (it was skipped in serialization; secret is lost after restart unless the user
        //  re-registers keys — this is correct: prekeys are ephemeral)
        store.crypto = None;
        Ok(store)
    }

    /// Save this keystore to disk at the specified path, encrypted with `encryption_key`.
    ///
    /// Uses atomic write (write to temp file, then rename) to avoid corruption.
    /// Existing file will be overwritten.
    ///
    /// # Feature
    /// Available without any feature flags — uses only `std::fs`.
    pub fn save_to_disk(&self, path: &std::path::Path, encryption_key: &[u8; 32]) -> ProtocolResult<()> {
        use std::io::Write;

        let encrypted = self.to_encrypted_bytes(encryption_key)?;

        // Atomic write: write to temp path, then rename
        let tmp_path = path.with_extension("tmp");

        let mut file = std::fs::File::create(&tmp_path)
            .map_err(|_| ProtocolError::StorageError)?;
        file.write_all(&encrypted)
            .map_err(|_| ProtocolError::StorageError)?;
        file.flush()
            .map_err(|_| ProtocolError::StorageError)?;
        drop(file);

        std::fs::rename(&tmp_path, path)
            .map_err(|_| ProtocolError::StorageError)?;

        Ok(())
    }

    /// Load a keystore from disk, decrypting with `encryption_key`.
    ///
    /// Returns `ProtocolError::StorageError` if the file does not exist or is corrupt.
    pub fn load_from_disk(path: &std::path::Path, encryption_key: &[u8; 32]) -> ProtocolResult<Self> {
        use std::io::Read;

        let mut file = std::fs::File::open(path)
            .map_err(|_| ProtocolError::StorageError)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|_| ProtocolError::StorageError)?;

        Self::from_encrypted_bytes(&data, encryption_key)
    }

    // ----------------------------------------------------------------
    // Ed25519 Challenge–Response
    // ----------------------------------------------------------------

    /// Generate a cryptographically secure 32-byte challenge for device authentication.
    ///
    /// The challenge must be sent to the remote device, which signs it with its
    /// Ed25519 identity key and returns the 64-byte signature. Use
    /// `verify_signed_challenge` to verify the response.
    pub fn generate_challenge() -> ProtocolResult<[u8; 32]> {
        use crate::crypto::SecureRandom;
        let mut rng = SecureRandom::new()?;
        let mut challenge = [0u8; 32];
        rng.fill_bytes(&mut challenge);
        Ok(challenge)
    }

    /// Verify that `signed_challenge` is a valid Ed25519 signature of `challenge`
    /// made by the device whose identity public key is `device_ed25519_pub`.
    ///
    /// This replaces the previous TODO that only checked device registration.
    ///
    /// # Arguments
    /// * `challenge` — 32-byte random challenge (from `generate_challenge`)
    /// * `signed_challenge` — 64-byte Ed25519 signature made by the device
    /// * `device_ed25519_pub` — Ed25519 public key of the device to authenticate
    ///
    /// # Returns
    /// `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
    /// `Err` on malformed inputs.
    pub fn verify_signed_challenge(
        challenge: &[u8; 32],
        signed_challenge: &[u8; 64],
        device_ed25519_pub: &[u8; 32],
    ) -> ProtocolResult<bool> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};

        let verifying_key = VerifyingKey::from_bytes(device_ed25519_pub)
            .map_err(|_| ProtocolError::InvalidKey)?;

        let signature = Signature::from_bytes(signed_challenge);

        match verifying_key.verify(challenge, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // ----------------------------------------------------------------
    // Key Pinning — MITM Detection
    // ----------------------------------------------------------------

    /// Pin a peer's identity key on first contact (Trust-On-First-Use).
    ///
    /// # Returns
    /// - `PinResult::NewPin` — first contact; key was pinned
    /// - `PinResult::Consistent` — key matches the stored pin; peer is the same
    /// - `PinResult::KeyChanged` — **key changed**; abort session and alert user
    pub fn pin_peer_key(&mut self, peer_id: &[u8], new_key: &[u8; 32]) -> PinResult {
        let our_identity = self
            .identity
            .as_ref()
            .map(|id| id.ed25519_public)
            .unwrap_or([0u8; 32]);

        match self.peer_pins.get(peer_id) {
            None => {
                let pin = PinnedKey::new(*new_key, &our_identity);
                self.peer_pins.insert(peer_id.to_vec(), pin);
                PinResult::NewPin
            }
            Some(existing) => {
                if constant_time_eq(&existing.identity_key, new_key) {
                    PinResult::Consistent
                } else {
                    PinResult::KeyChanged {
                        pinned_key: existing.identity_key,
                        new_key: *new_key,
                    }
                }
            }
        }
    }

    /// Pin or verify a peer key; return `Err(KeyMismatch)` if the key changed.
    ///
    /// Used by `SecureContext::perform_handshake` to abort automatically on MITM.
    pub fn verify_or_pin_peer_key(
        &mut self,
        peer_id: &[u8],
        new_key: &[u8; 32],
    ) -> ProtocolResult<PinResult> {
        match self.pin_peer_key(peer_id, new_key) {
            PinResult::KeyChanged { .. } => Err(ProtocolError::KeyMismatch),
            other => Ok(other),
        }
    }

    /// Get the pinned key record for a peer, if any.
    pub fn get_peer_pin(&self, peer_id: &[u8]) -> Option<&PinnedKey> {
        self.peer_pins.get(peer_id)
    }

    /// Mark a peer's pinned key as verified after Safety Number comparison.
    pub fn mark_peer_verified(&mut self, peer_id: &[u8]) {
        if let Some(pin) = self.peer_pins.get_mut(peer_id) {
            pin.verified = true;
        }
    }

    /// Remove a peer pin (e.g. when peer re-registers and user confirms new key).
    pub fn remove_peer_pin(&mut self, peer_id: &[u8]) {
        self.peer_pins.remove(peer_id);
    }

    /// Return all pinned peer IDs.
    pub fn pinned_peers(&self) -> Vec<Vec<u8>> {
        self.peer_pins.keys().cloned().collect()
    }
}

impl Zeroize for KeyStore {
    fn zeroize(&mut self) {
        self.identity = None;
        self.signed_prekey = None;
        self.onetime_prekeys.clear();
        self.next_onetime_id = 0;
        self.peer_pins.clear();
    }
}

impl ZeroizeOnDrop for KeyStore {}

impl Drop for KeyStore {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Key store statistics
#[derive(Clone, Debug)]
pub struct KeyStoreStats {
    /// Whether identity key exists
    pub has_identity: bool,
    /// Whether signed prekey exists
    pub has_signed_prekey: bool,
    /// Available one-time prekeys
    pub onetime_prekey_count: usize,
    /// Total one-time prekeys (including used)
    pub total_onetime_prekeys: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_keypair_generation() {
        let keypair = IdentityKeyPair::generate();
        
        assert!(!constant_time_is_zero(&keypair.ed25519_public));
        assert!(!constant_time_is_zero(&keypair.x25519_public));
        assert!(keypair.is_valid());
    }

    #[test]
    fn test_identity_keypair_sign_verify() {
        let keypair = IdentityKeyPair::generate();
        
        let data = b"test data";
        let signature = keypair.sign(data).unwrap();
        
        assert!(keypair.verify(data, &signature).unwrap());
        assert!(!keypair.verify(b"wrong data", &signature).unwrap());
    }

    #[test]
    fn test_signed_prekey() {
        let identity = IdentityKeyPair::generate();
        let prekey = SignedPreKey::generate(1, &identity).unwrap();
        
        assert_eq!(prekey.key_id, 1);
        assert!(prekey.verify(&identity).unwrap());
    }

    #[test]
    fn test_onetime_prekey() {
        let mut prekey = OneTimePreKey::generate(1);
        
        assert_eq!(prekey.key_id, 1);
        assert!(!prekey.used);
        
        prekey.mark_used();
        assert!(prekey.used);
        assert!(prekey.secret.is_none());
    }

    #[test]
    fn test_keystore() {
        let mut keystore = KeyStore::new().unwrap();
        
        // Set identity
        let identity = IdentityKeyPair::generate();
        keystore.set_identity(identity).unwrap();
        
        // Generate signed prekey
        keystore.generate_signed_prekey().unwrap();
        assert!(keystore.get_signed_prekey().is_ok());
        
        // Generate one-time prekeys
        let ids = keystore.generate_onetime_prekeys(5).unwrap();
        assert_eq!(ids.len(), 5);
        assert_eq!(keystore.onetime_prekey_count(), 5);
        
        // Use a one-time prekey
        let (id, _) = keystore.get_onetime_prekey_public().unwrap();
        keystore.mark_onetime_used(id);
        assert_eq!(keystore.onetime_prekey_count(), 4);
    }

    #[test]
    fn test_keystore_stats() {
        let mut keystore = KeyStore::new().unwrap();
        
        let stats = keystore.stats();
        assert!(!stats.has_identity);
        
        let identity = IdentityKeyPair::generate();
        keystore.set_identity(identity).unwrap();
        
        let stats = keystore.stats();
        assert!(stats.has_identity);
    }

    #[test]
    fn test_generate_challenge() {
        let c1 = KeyStore::generate_challenge().unwrap();
        let c2 = KeyStore::generate_challenge().unwrap();
        // Challenges must be unique
        assert_ne!(c1, c2);
        // Challenge must not be all zeros
        assert!(!c1.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_verify_signed_challenge_valid() {
        use ed25519_dalek::{SigningKey, Signer};
        use rand_core::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_pub = signing_key.verifying_key().to_bytes();

        let challenge = KeyStore::generate_challenge().unwrap();
        let signature = signing_key.sign(&challenge).to_bytes();

        let result = KeyStore::verify_signed_challenge(&challenge, &signature, &ed25519_pub).unwrap();
        assert!(result, "Valid challenge-response must pass verification");
    }

    #[test]
    fn test_verify_signed_challenge_invalid() {
        use ed25519_dalek::{SigningKey, Signer};
        use rand_core::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_pub = signing_key.verifying_key().to_bytes();

        let challenge = KeyStore::generate_challenge().unwrap();
        let wrong_challenge = KeyStore::generate_challenge().unwrap();
        // Sign a different challenge than the one being verified
        let signature = signing_key.sign(&wrong_challenge).to_bytes();

        let result = KeyStore::verify_signed_challenge(&challenge, &signature, &ed25519_pub).unwrap();
        assert!(!result, "Signature over wrong challenge must fail");
    }

    #[test]
    fn test_keystore_encrypted_bytes_roundtrip() {
        let mut keystore = KeyStore::new().unwrap();
        let identity = IdentityKeyPair::generate();
        keystore.set_identity(identity).unwrap();
        keystore.generate_signed_prekey().unwrap();
        keystore.generate_onetime_prekeys(3).unwrap();

        // Use a valid (non-weak) key
        let encryption_key: [u8; 32] = {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i + 1) as u8;
            }
            k
        };

        let encrypted = keystore.to_encrypted_bytes(&encryption_key).unwrap();
        let loaded = KeyStore::from_encrypted_bytes(&encrypted, &encryption_key).unwrap();

        // Public keys must survive the round-trip
        let orig_spk = keystore.get_signed_prekey_public().unwrap();
        let loaded_spk = loaded.get_signed_prekey_public().unwrap();
        assert_eq!(orig_spk, loaded_spk);
        assert_eq!(keystore.onetime_prekey_count(), loaded.onetime_prekey_count());
    }

    #[test]
    fn test_keystore_disk_roundtrip() {
        let mut keystore = KeyStore::new().unwrap();
        let identity = IdentityKeyPair::generate();
        keystore.set_identity(identity).unwrap();
        keystore.generate_signed_prekey().unwrap();

        let encryption_key: [u8; 32] = {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() { *b = (i + 1) as u8; }
            k
        };

        let tmp_dir = std::env::temp_dir();
        let path = tmp_dir.join("sibna_keystore_test_v10.bin");

        keystore.save_to_disk(&path, &encryption_key).unwrap();
        let loaded = KeyStore::load_from_disk(&path, &encryption_key).unwrap();

        let orig_spk = keystore.get_signed_prekey_public().unwrap();
        let loaded_spk = loaded.get_signed_prekey_public().unwrap();
        assert_eq!(orig_spk, loaded_spk, "Signed prekey public must survive disk round-trip");

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_get_prekey_bundle_data() {
        let mut keystore = KeyStore::new().unwrap();
        let identity = IdentityKeyPair::generate();
        keystore.set_identity(identity).unwrap();
        keystore.generate_signed_prekey().unwrap();
        keystore.generate_onetime_prekeys(1).unwrap();

        let (ik, spk, sig, opk) = keystore.get_prekey_bundle_data().unwrap();

        // Identity key and signed prekey must be non-zero
        assert!(!ik.iter().all(|&b| b == 0));
        assert!(!spk.iter().all(|&b| b == 0));
        assert!(!sig.iter().all(|&b| b == 0));
        assert!(opk.is_some());
    }
}
