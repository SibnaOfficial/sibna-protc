//! X3DH Handshake Implementation
//!
//! Implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol
//! as specified in the Signal Protocol.

mod builder;
pub mod x3dh;

pub use builder::*;
pub use x3dh::*;

use crate::error::{ProtocolResult, ProtocolError};
use crate::crypto::constant_time_eq;
use x25519_dalek::{StaticSecret, PublicKey};

/// Size of ML-KEM-768 (Kyber) public key
pub const PQ_PUBLIC_KEY_SIZE: usize = 1184;
/// Size of ML-KEM-768 (Kyber) ciphertext
pub const PQ_CIPHERTEXT_SIZE: usize = 1088;
/// Size of ML-KEM-768 (Kyber) shared secret
pub const PQ_SHARED_SECRET_SIZE: usize = 32;

/// Handshake result containing shared secrets and keys
/// Errors specific to the handshake process
#[derive(Debug, Clone)]
pub enum HandshakeError {
    /// Protocol state is invalid for this operation
    InvalidState,
    /// Key material is invalid
    InvalidKey,
    /// Handshake timed out
    Timeout,
    /// Signature verification failed
    SignatureVerification,
    /// Missing required key
    MissingKey,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState          => write!(f, "Invalid handshake state"),
            Self::InvalidKey            => write!(f, "Invalid key material"),
            Self::Timeout               => write!(f, "Handshake timed out"),
            Self::SignatureVerification => write!(f, "Signature verification failed"),
            Self::MissingKey            => write!(f, "Missing required key"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<HandshakeError> for crate::error::ProtocolError {
    fn from(e: HandshakeError) -> Self {
        match e {
            HandshakeError::InvalidState          => Self::InvalidState,
            HandshakeError::InvalidKey            => Self::InvalidKey,
            HandshakeError::Timeout               => Self::Timeout,
            HandshakeError::SignatureVerification => Self::InvalidSignature,
            HandshakeError::MissingKey            => Self::KeyNotFound,
        }
    }
}

/// Output of a successful handshake
pub struct HandshakeOutput {
    /// The shared secret derived from the handshake
    pub shared_secret: [u8; 32],
    /// Local ephemeral key pair
    pub local_ephemeral_key: StaticSecret,
    /// Local ephemeral public key
    pub local_ephemeral_public: PublicKey,
    /// Post-Quantum Ciphertext
    #[cfg(feature = "pqc")]
    pub pq_ciphertext: Option<Vec<u8>>,
    /// Associated data for session binding
    pub associated_data: Vec<u8>,
    /// Handshake timestamp
    pub timestamp: u64,
}

impl HandshakeOutput {
    /// Create a new handshake output
    pub fn new(
        shared_secret: [u8; 32],
        local_ephemeral_key: StaticSecret,
        local_ephemeral_public: PublicKey,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            shared_secret,
            local_ephemeral_key,
            local_ephemeral_public,
            #[cfg(feature = "pqc")]
            pq_ciphertext: None,
            associated_data: Vec::new(),
            timestamp,
        }
    }

    /// Set Post-Quantum ciphertext
    #[cfg(feature = "pqc")]
    pub fn with_pq_ciphertext(mut self, ct: Vec<u8>) -> Self {
        self.pq_ciphertext = Some(ct);
        self
    }

    /// Set associated data
    pub fn with_associated_data(mut self, ad: Vec<u8>) -> Self {
        self.associated_data = ad;
        self
    }

    /// Validate the handshake output
    pub fn validate(&self) -> ProtocolResult<()> {
        // Check shared secret is not all zeros
        if self.shared_secret.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidArgument);
        }

        // Check ephemeral key is valid
        let public = PublicKey::from(&self.local_ephemeral_key);
        if !constant_time_eq(public.as_bytes(), self.local_ephemeral_public.as_bytes()) {
            return Err(ProtocolError::InvalidArgument);
        }

        Ok(())
    }
}

impl std::fmt::Debug for HandshakeOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeOutput")
            .field("shared_secret", &"[REDACTED]")
            .field("local_ephemeral_public", &self.local_ephemeral_public)
            .field("associated_data_len", &self.associated_data.len())
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Handshake role (initiator or responder)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Initiator of the handshake
    Initiator,
    /// Responder to the handshake
    Responder,
}

/// Handshake state
#[derive(Clone, Debug)]
pub enum HandshakeState {
    /// Initial state
    Initial,
    /// Keys loaded
    KeysLoaded,
    /// Handshake in progress
    InProgress,
    /// Handshake completed
    Completed,
    /// Handshake failed
    Failed(String),
}

/// Prekey bundle for X3DH
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Identity key (Ed25519 public key)
    pub identity_key: [u8; 32],
    /// Signed prekey (X25519 public key)
    pub signed_prekey: [u8; 32],
    /// Signature of signed prekey
    pub signature: [u8; 64],
    /// One-time prekey (optional, X25519 public key)
    pub onetime_prekey: Option<[u8; 32]>,
    /// Unique identifier for this bundle
    pub bundle_id: [u8; 16],
    /// Timestamp of bundle creation
    pub timestamp: u64,
    /// Expiration timestamp
    pub expiration: u64,
    
    /// The ID of this specific device (0 for master device)
    pub device_id: u32,
    /// The Root Identity Key of the user (Ed25519 public key)
    pub root_identity_key: [u8; 32],
    /// Signature from the Root Key proving this device belongs to it over (device_identity_key || device_id)
    pub device_signature: [u8; 64],

    /// Signature over the entire bundle payload (Ed25519 signature by device identity_key)
    pub bundle_signature: [u8; 64],

    /// Post-Quantum public key (ML-KEM-768)
    #[cfg(feature = "pqc")]
    pub pq_signed_prekey: Option<Vec<u8>>,
    /// Signature of the PQ public key by the identity key
    #[cfg(feature = "pqc")]
    pub pq_signed_prekey_signature: Option<[u8; 64]>,
}

impl PreKeyBundle {
    /// Create a new prekey bundle
    pub fn new(
        identity_key: [u8; 32],
        signed_prekey: [u8; 32],
        signature: [u8; 64],
        onetime_prekey: Option<[u8; 32]>,
        device_id: u32,
        root_identity_key: [u8; 32],
        device_signature: [u8; 64],
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Expire in 30 days
        let expiration = timestamp + 30 * 86400;
        
        let mut bundle_id = [0u8; 16];
        use rand_core::{RngCore, OsRng};
        OsRng.fill_bytes(&mut bundle_id);

        Self {
            identity_key,
            signed_prekey,
            signature,
            onetime_prekey,
            bundle_id,
            timestamp,
            expiration,
            device_id,
            root_identity_key,
            device_signature,
            bundle_signature: [0u8; 64], // Unsigned by default
            #[cfg(feature = "pqc")]
            pq_signed_prekey: None,
            #[cfg(feature = "pqc")]
            pq_signed_prekey_signature: None,
        }
    }

    /// Set the Post-Quantum prekey and its signature
    #[cfg(feature = "pqc")]
    pub fn with_pq_prekey(mut self, pk: Vec<u8>, sig: [u8; 64]) -> Self {
        self.pq_signed_prekey = Some(pk);
        self.pq_signed_prekey_signature = Some(sig);
        self
    }

    /// Sign the entire bundle payload
    pub fn sign_bundle<F>(&mut self, signer: F) -> ProtocolResult<()>
    where
        F: FnOnce(&[u8]) -> ProtocolResult<[u8; 64]>,
    {
        let payload = self.signing_bytes();
        self.bundle_signature = signer(&payload)?;
        Ok(())
    }

    /// Get bytes for signing/verifying the bundle
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(200);
        result.extend_from_slice(&self.identity_key);
        result.extend_from_slice(&self.signed_prekey);
        result.extend_from_slice(&self.signature);
        result.push(self.onetime_prekey.is_some() as u8);
        if let Some(ref opk) = self.onetime_prekey {
            result.extend_from_slice(opk);
        }
        result.extend_from_slice(&self.bundle_id);
        result.extend_from_slice(&self.timestamp.to_le_bytes());
        result.extend_from_slice(&self.expiration.to_le_bytes());
        result.extend_from_slice(&self.device_id.to_le_bytes());
        result.extend_from_slice(&self.root_identity_key);
        result.extend_from_slice(&self.device_signature);
        
        #[cfg(feature = "pqc")]
        {
            result.push(self.pq_signed_prekey.is_some() as u8);
            if let Some(ref pk) = self.pq_signed_prekey {
                result.extend_from_slice(pk);
            }
            if let Some(ref sig) = self.pq_signed_prekey_signature {
                result.extend_from_slice(sig);
            }
        }

        result
    }

    /// Validate the prekey bundle
    pub fn validate(&self) -> ProtocolResult<()> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        
        // Check keys are not all zeros
        if self.identity_key.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidKey);
        }
        if self.signed_prekey.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidKey);
        }

        // Verify signed_prekey signature
        let verifying_key = VerifyingKey::from_bytes(&self.identity_key)
            .map_err(|_| ProtocolError::InvalidKey)?;
        let spk_signature = Signature::from_bytes(&self.signature);

        verifying_key.verify(&self.signed_prekey, &spk_signature)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        // Verify full bundle signature
        let bundle_sig = Signature::from_bytes(&self.bundle_signature);
        let payload = self.signing_bytes();
        verifying_key.verify(&payload, &bundle_sig)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        // Verify device linking signature by Root Key
        let root_key = VerifyingKey::from_bytes(&self.root_identity_key)
            .map_err(|_| ProtocolError::InvalidKey)?;
        let dev_sig = Signature::from_bytes(&self.device_signature);
        
        let mut dev_payload = Vec::with_capacity(36);
        dev_payload.extend_from_slice(&self.identity_key);
        dev_payload.extend_from_slice(&self.device_id.to_le_bytes());
        
        root_key.verify(&dev_payload, &dev_sig)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        // Verify PQ prekey signature if present
        #[cfg(feature = "pqc")]
        if let Some(ref pk) = self.pq_signed_prekey {
            if pk.len() != 1184 {
                return Err(ProtocolError::InvalidKeyLength);
            }
            if let Some(sig) = self.pq_signed_prekey_signature {
                let sig = ed25519_dalek::Signature::from_bytes(&sig);
                verifying_key.verify(pk, &sig)
                    .map_err(|_| ProtocolError::InvalidSignature)?;
            } else {
                return Err(ProtocolError::InvalidSignature);
            }
        }

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        if now > self.expiration {
            return Err(ProtocolError::Expired);
        }

        Ok(())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = self.signing_bytes();
        result.extend_from_slice(&self.bundle_signature);
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        // Minimum non-PQC size: ik(32)+spk(32)+sig(64)+has_opk(1)+bundle_id(16)+ts(8)+exp(8)+dev_id(4)+root(32)+dev_sig(64)+bundle_sig(64) = 325 bytes
        if data.len() < 325 {
            return Err(ProtocolError::InvalidMessage);
        }

        // The bundle signature is always the last 64 bytes
        let sig_start = data.len() - 64;
        let mut bundle_signature = [0u8; 64];
        bundle_signature.copy_from_slice(&data[sig_start..]);

        // The remaining bytes are the signing payload
        let data = &data[..sig_start];

        let mut offset = 0;
        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&data[offset..offset+32]); offset += 32;

        let mut signed_prekey = [0u8; 32];
        signed_prekey.copy_from_slice(&data[offset..offset+32]); offset += 32;

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[offset..offset+64]); offset += 64;

        let has_onetime = data[offset] != 0; offset += 1;
        let onetime_prekey = if has_onetime {
            let mut opk = [0u8; 32];
            opk.copy_from_slice(&data[offset..offset+32]); offset += 32;
            Some(opk)
        } else {
            None
        };

        if data.len() < offset + 16 + 8 + 8 + 64 {
            return Err(ProtocolError::InvalidMessage);
        }

        let mut bundle_id = [0u8; 16];
        bundle_id.copy_from_slice(&data[offset..offset+16]); offset += 16;

        let timestamp = u64::from_le_bytes(data[offset..offset+8].try_into().map_err(|_| ProtocolError::InvalidMessage)?); offset += 8;
        let expiration = u64::from_le_bytes(data[offset..offset+8].try_into().map_err(|_| ProtocolError::InvalidMessage)?); offset += 8;

        if data.len() < offset + 4 + 32 + 64 {
            return Err(ProtocolError::InvalidMessage);
        }

        let device_id = u32::from_le_bytes(data[offset..offset+4].try_into().map_err(|_| ProtocolError::InvalidMessage)?); offset += 4;
        
        let mut root_identity_key = [0u8; 32];
        root_identity_key.copy_from_slice(&data[offset..offset+32]); offset += 32;

        let mut device_signature = [0u8; 64];
        device_signature.copy_from_slice(&data[offset..offset+64]); offset += 64;

        #[cfg(feature = "pqc")]
        let (pq_signed_prekey, pq_signed_prekey_signature) = if offset < data.len() {
            let has_pq = data[offset] != 0; offset += 1;
            if has_pq && offset + 1184 + 64 <= data.len() {
                let mut pq_pk = vec![0u8; 1184];
                pq_pk.copy_from_slice(&data[offset..offset + 1184]);
                offset += 1184;
                let mut pq_sig = [0u8; 64];
                pq_sig.copy_from_slice(&data[offset..offset + 64]);
                // offset += 64; // Implicitly at the end
                (Some(pq_pk), Some(pq_sig))
            } else {
                // BUG FIX: Downgrade Protection
                // If the PQC feature is enabled, we REQUIRE the peer to provide a PQC bundle 
                // if they are on a compatible version.
                return Err(ProtocolError::InvalidMessage);
            }
        } else {
            // No PQC data present. If we enforce PQC, this is a failure.
            return Err(ProtocolError::InvalidMessage);
        };
#[cfg(not(feature = "pqc"))]
        let (pq_signed_prekey, pq_signed_prekey_signature) = (None, None);

        Ok(Self {
            identity_key,
            signed_prekey,
            signature,
            onetime_prekey,
            bundle_id,
            timestamp,
            expiration,
            device_id,
            root_identity_key,
            device_signature,
            bundle_signature,
            #[cfg(feature = "pqc")]
            pq_signed_prekey,
            #[cfg(feature = "pqc")]
            pq_signed_prekey_signature,
        })
    }
}

/// Handshake metrics for monitoring
#[derive(Clone, Debug, Default)]
pub struct HandshakeMetrics {
    /// Number of successful handshakes
    pub successful: u64,
    /// Number of failed handshakes
    pub failed: u64,
    /// Average handshake time in milliseconds
    pub avg_time_ms: f64,
    /// Total handshakes
    pub total: u64,
}

impl HandshakeMetrics {
    /// Record a successful handshake
    pub fn record_success(&mut self, duration_ms: f64) {
        self.successful += 1;
        self.total += 1;
        // Update running average
        self.avg_time_ms = (self.avg_time_ms * (self.total - 1) as f64 + duration_ms) / self.total as f64;
    }

    /// Record a failed handshake
    pub fn record_failure(&mut self) {
        self.failed += 1;
        self.total += 1;
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.successful as f64 / self.total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand_core::OsRng;

    #[test]
    fn test_handshake_output_validation() {
        let ephemeral = StaticSecret::random_from_rng(&mut OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral);

        let output = HandshakeOutput::new(
            [0x42u8; 32],
            ephemeral,
            ephemeral_public,
        );

        assert!(output.validate().is_ok());
    }

    #[test]
    fn test_handshake_output_invalid() {
        let ephemeral = StaticSecret::random_from_rng(&mut OsRng);
        let ephemeral_public = PublicKey::from(&StaticSecret::random_from_rng(&mut OsRng));

        let output = HandshakeOutput::new(
            [0u8; 32], // Invalid shared secret
            ephemeral,
            ephemeral_public,
        );

        assert!(output.validate().is_err());
    }

    #[test]
    fn test_prekey_bundle_validation() {
        // Generate signing key
        let signing_key = SigningKey::generate(&mut OsRng);
        let identity_key = signing_key.verifying_key().to_bytes();

        // Generate signed prekey
        let signed_prekey_secret = StaticSecret::random_from_rng(&mut OsRng);
        let signed_prekey = PublicKey::from(&signed_prekey_secret).to_bytes();

        // Sign the prekey
        let signature = signing_key.sign(&signed_prekey).to_bytes();

        // Master device identity signature
        let mut dev_payload = Vec::with_capacity(36);
        dev_payload.extend_from_slice(&identity_key);
        dev_payload.extend_from_slice(&0u32.to_le_bytes());
        let device_signature = signing_key.sign(&dev_payload).to_bytes();

        let mut bundle = PreKeyBundle::new(
            identity_key,
            signed_prekey,
            signature,
            None,
            0,
            identity_key,
            device_signature,
        );

        bundle.sign_bundle(|data| Ok(signing_key.sign(data).to_bytes())).unwrap();

        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_prekey_bundle_invalid_signature() {
        let identity_key = [0x42u8; 32];
        let signed_prekey = [0x24u8; 32];
        let signature = [0u8; 64]; // Invalid signature

        let bundle = PreKeyBundle::new(
            identity_key,
            signed_prekey,
            signature,
            None,
            0,
            identity_key,
            [0u8; 64],
        );

        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_prekey_bundle_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let identity_key = signing_key.verifying_key().to_bytes();

        let signed_prekey_secret = StaticSecret::random_from_rng(&mut OsRng);
        let signed_prekey = PublicKey::from(&signed_prekey_secret).to_bytes();

        let signature = signing_key.sign(&signed_prekey).to_bytes();

        let mut dev_payload = Vec::with_capacity(36);
        dev_payload.extend_from_slice(&identity_key);
        dev_payload.extend_from_slice(&0u32.to_le_bytes());
        let device_signature = signing_key.sign(&dev_payload).to_bytes();

        let mut bundle = PreKeyBundle::new(
            identity_key,
            signed_prekey,
            signature,
            Some([0xABu8; 32]),
            0,
            identity_key,
            device_signature,
        );

        #[cfg(feature = "pqc")]
        {
            let pq_pk = vec![0u8; 1184];
            let pq_sig = [0u8; 64];
            bundle = bundle.with_pq_prekey(pq_pk, pq_sig);
        }

        let bytes = bundle.to_bytes();
        let parsed = PreKeyBundle::from_bytes(&bytes).unwrap();

        assert_eq!(bundle.identity_key, parsed.identity_key);
        assert_eq!(bundle.signed_prekey, parsed.signed_prekey);
        assert_eq!(bundle.signature, parsed.signature);
        assert_eq!(bundle.onetime_prekey, parsed.onetime_prekey);
    }

    #[test]
    fn test_handshake_metrics() {
        let mut metrics = HandshakeMetrics::default();

        metrics.record_success(100.0);
        metrics.record_success(200.0);
        metrics.record_failure();

        assert_eq!(metrics.successful, 2);
        assert_eq!(metrics.failed, 1);
        assert_eq!(metrics.total, 3);
        assert!((metrics.success_rate() - 0.6667).abs() < 0.001);
    }
}
