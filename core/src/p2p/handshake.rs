//! P2P Handshake — inline X3DH without a server
//!
//! Two peers exchange PreKey Bundles and X3DH envelopes directly over TCP
//! and establish a Double Ratchet session without any server involvement.
//!
//! ## Wire protocol (3-message handshake)
//!
//! ```text
//! Initiator (Alice)                    Responder (Bob)
//! ─────────────────                    ───────────────
//!  1. → P2pMsg::Hello  (version, ed25519_pub, x25519_pub)
//!                         ──────────────────────────────►
//!  (← P2pMsg::Bundle)           2. Bob sends PreKeyBundle
//!                         ◄──────────────────────────────
//!  3. → P2pMsg::Envelope   (X3DH ephemeral key + intent)
//!                         ──────────────────────────────►
//!                                          4. Bob confirms
//!  (← P2pMsg::Ok)          ◄──────────────────────────────
//! ```
//!
//! All `P2pMsg` frames are encoded with `bincode` then framed by the
//! length-delimited codec in `transport.rs`.

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use x25519_dalek::{StaticSecret, PublicKey};
use zeroize::Zeroize;

use crate::{
    handshake::PreKeyBundle,
    keystore::IdentityKeyPair,
    ratchet::DoubleRatchetSession,
    Config,
};
use super::{P2pError, P2pResult};

/// Configuration for the P2P handshake phase.
#[derive(Clone, Debug)]
pub struct P2pHandshakeConfig {
    /// Seconds before handshake times out
    pub timeout_secs: u64,
    /// Max frame bytes — must match transport
    pub max_frame_bytes: usize,
}

impl Default for P2pHandshakeConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_frame_bytes: 10 * 1024 * 1024,
        }
    }
}


// ── Stealth Handshake Structs (Internal) ──────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct StealthBundle {
    responder_ed25519_pub: [u8; 32],
    responder_x25519_pub: [u8; 32],
    responder_device_id: [u8; 16],
    bundle_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct StealthEnvelope {
    initiator_ed25519_pub: [u8; 32],
    initiator_x25519_pub: [u8; 32],
    initiator_device_id: [u8; 16],
    ephemeral_pub: [u8; 32],
    signed_prekey_used: [u8; 32],
    onetime_prekey_used: Option<[u8; 32]>,
    #[cfg(feature = "pqc")]
    pq_ciphertext: Option<Vec<u8>>,
}

// ── Wire messages ──────────────────────────────────────────────────────────

/// All messages exchanged during a P2P handshake. Encoded with `bincode`.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum P2pMsg {
    /// Step 1 (Initiator → Responder): announce ephemeral public key and device ID.
    Hello {
        /// Protocol wire version byte
        version: u8,
        /// Initiator's ephemeral X25519 public key
        ephemeral_pub: [u8; 32],
        /// Initiator's device ID (to prevent state collision)
        initiator_device_id: [u8; 16],
    },
    /// Step 2 (Responder → Initiator): provide encrypted bundle.
    Bundle {
        /// Responder's ephemeral X25519 public key
        ephemeral_pub: [u8; 32],
        /// AEAD encrypted `StealthBundle` payload
        encrypted_bundle: Vec<u8>,
    },
    /// Step 3 (Initiator → Responder): provide encrypted envelope.
    Envelope {
        /// AEAD encrypted `StealthEnvelope` payload
        encrypted_envelope: Vec<u8>,
    },
    /// Step 4 (Responder → Initiator): confirm that handshake is complete.
    Ok {
        /// AEAD encrypted confirm signal
        encrypted_ok: Vec<u8>,
    },
    /// Error signal.
    Error {
        reason: String,
    },
}

use crate::crypto::{CryptoHandler, SimpleKdf};

/// Bumped on any breaking wire-format change.
const P2P_PROTOCOL_VERSION: u8 = 2; // v2.0 Fortress

// ── Serialisation & Handshake Crypto ───────────────────────────────────────

pub(crate) fn encode_msg(msg: &P2pMsg) -> P2pResult<Bytes> {
    bincode::serialize(msg)
        .map(Bytes::from)
        .map_err(|e| P2pError::Framing(e.to_string()))
}

pub(crate) fn decode_msg(bytes: &[u8]) -> P2pResult<P2pMsg> {
    bincode::deserialize(bytes)
        .map_err(|e| P2pError::InvalidMessage(e.to_string()))
}

/// Derive a transient key for protecting the handshake identity exchange.
fn derive_handshake_key(
    our_ephemeral: &StaticSecret,
    peer_ephemeral_pub: &PublicKey,
) -> P2pResult<CryptoHandler> {
    let shared = our_ephemeral.diffie_hellman(peer_ephemeral_pub);
    let key = SimpleKdf::derive_sha256(shared.as_bytes(), b"SibnaHandshake_v2.0")
        .map_err(|e| P2pError::Crypto(e.to_string()))?;
    
    CryptoHandler::new(key.as_ref())
        .map_err(|e| P2pError::Crypto(e.to_string()))
}

// ── Initiator side ─────────────────────────────────────────────────────────

/// Run the **initiator** (Alice) side of the P2P handshake.
///
/// Returns a ready `DoubleRatchetSession` and the responder's Ed25519 public
/// key bytes (usable as a stable peer identity).
pub async fn initiator_handshake(
    stream: &mut super::transport::FramedStream,
    identity: &IdentityKeyPair,
    protocol_config: Config,
    handshake_cfg: &P2pHandshakeConfig,
    our_device_id: [u8; 16],
) -> P2pResult<(DoubleRatchetSession, [u8; 32])> {
    let timeout = tokio::time::Duration::from_secs(handshake_cfg.timeout_secs);

    tokio::time::timeout(timeout, async {
        // ── 1. Send Hello (Ephemeral + DeviceID) ───────────────────────
        let alice_ephemeral = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let alice_ephemeral_pub = PublicKey::from(&alice_ephemeral);

        stream.send(encode_msg(&P2pMsg::Hello {
            version: P2P_PROTOCOL_VERSION,
            ephemeral_pub: *alice_ephemeral_pub.as_bytes(),
            initiator_device_id: our_device_id,
        })?).await
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())))?;

        // ── 2. Receive Bundle (Encrypted) ──────────────────────────────
        let frame = stream.next().await.ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        
        let (bob_ephemeral_pub, encrypted_bundle) = match decode_msg(&frame)? {
            P2pMsg::Bundle { ephemeral_pub, encrypted_bundle } => {
                let pub_key = PublicKey::from(ephemeral_pub);
                crate::crypto::validate_public_key(pub_key.as_bytes())
                    .map_err(|_| P2pError::Handshake("invalid responder ephemeral key".into()))?;
                (pub_key, encrypted_bundle)
            },
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => return Err(P2pError::InvalidMessage(format!("expected Bundle, got {:?}", other))),
        };

        let handler = derive_handshake_key(&alice_ephemeral, &bob_ephemeral_pub)?;

        let bundle_payload = handler.decrypt(&encrypted_bundle, b"handshake_bundle")
            .map_err(|_| P2pError::Handshake("failed to decrypt bundle".into()))?;
        let stealth_bundle: StealthBundle = bincode::deserialize(&bundle_payload)
            .map_err(|e| P2pError::Handshake(format!("malformed stealth bundle: {}", e)))?;

        let bundle = PreKeyBundle::from_bytes(&stealth_bundle.bundle_bytes)
            .map_err(|e| P2pError::Handshake(format!("malformed internal bundle: {:?}", e)))?;
        bundle.validate()
            .map_err(|e| P2pError::Handshake(format!("bundle validation: {:?}", e)))?;

        // ── Transcript Binding (v2.0) ──────────────────────────────────
        let mut hasher = blake3::Hasher::new();
        hasher.update(alice_ephemeral_pub.as_bytes());
        hasher.update(bob_ephemeral_pub.as_bytes());
        hasher.update(&our_device_id);
        hasher.update(&stealth_bundle.responder_device_id);
        hasher.update(&identity.ed25519_public);
        hasher.update(&stealth_bundle.responder_ed25519_pub);
        let transcript_hash = hasher.finalize();

        // ── Run X3DH initiator ─────────────────────────────────────────
        let x3dh_ephemeral = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let x3dh_ephemeral_pub = PublicKey::from(&x3dh_ephemeral);

        let our_identity_x = identity.x25519_secret.as_ref()
            .ok_or_else(|| P2pError::Crypto("identity X25519 secret not available".into()))?;

        let peer_identity_x = PublicKey::from(stealth_bundle.responder_x25519_pub);
        let peer_spk_pub    = PublicKey::from(bundle.signed_prekey);
        let peer_opk_pub    = bundle.onetime_prekey.map(PublicKey::from);

        #[cfg(feature = "pqc")]
        let mut x3dh_result = crate::handshake::x3dh::x3dh_initiator_v10(
            our_identity_x,
            &x3dh_ephemeral,
            &peer_identity_x,
            &peer_spk_pub,
            peer_opk_pub.as_ref(),
            bundle.pq_signed_prekey.as_ref(),
            transcript_hash.as_bytes(),
        ).map_err(|e| P2pError::Handshake(format!("x3dh_initiator: {:?}", e)))?;

        #[cfg(not(feature = "pqc"))]
        let mut x3dh_result = crate::handshake::x3dh::x3dh_initiator_v10(
            our_identity_x,
            &x3dh_ephemeral,
            &peer_identity_x,
            &peer_spk_pub,
            peer_opk_pub.as_ref(),
            transcript_hash.as_bytes(),
        ).map_err(|e| P2pError::Handshake(format!("x3dh_initiator: {:?}", e)))?;

        // ── 3. Send Envelope (Encrypted) ───────────────────────────────
        let stealth_envelope = StealthEnvelope {
            initiator_ed25519_pub: identity.ed25519_public,
            initiator_x25519_pub: identity.x25519_public,
            initiator_device_id: our_device_id,
            ephemeral_pub: *x3dh_ephemeral_pub.as_bytes(),
            signed_prekey_used: bundle.signed_prekey,
            onetime_prekey_used: bundle.onetime_prekey,
            #[cfg(feature = "pqc")]
            pq_ciphertext: x3dh_result.pq_ciphertext.take(),
        };
        let envelope_payload = bincode::serialize(&stealth_envelope)
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        let encrypted_envelope = handler.encrypt(&envelope_payload, b"handshake_envelope")
            .map_err(|_| P2pError::Crypto("failed to encrypt envelope".into()))?;

        stream.send(encode_msg(&P2pMsg::Envelope {
            encrypted_envelope,
        })?).await
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())))?;

        // ── 4. Receive Ok (Encrypted) ──────────────────────────────────
        let frame = stream.next().await.ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        
        let encrypted_ok = match decode_msg(&frame)? {
            P2pMsg::Ok { encrypted_ok } => encrypted_ok,
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => return Err(P2pError::InvalidMessage(format!("expected Ok, got {:?}", other))),
        };

        let _ = handler.decrypt(&encrypted_ok, b"handshake_ok")
            .map_err(|_| P2pError::Handshake("failed to decrypt ok signal".into()))?;

        // Build Double Ratchet session
        let remote_dh = PublicKey::from(bundle.signed_prekey);
        let mut shared_secret = x3dh_result.shared_secret;
        let session = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            x3dh_ephemeral,
            remote_dh,
            protocol_config,
            true,
        ).map_err(|e| P2pError::Crypto(format!("ratchet init: {:?}", e)))?;

        shared_secret.zeroize();

        Ok((session, stealth_bundle.responder_ed25519_pub))
    })
    .await
    .map_err(|_| P2pError::Timeout)?
}

// ── Responder side ─────────────────────────────────────────────────────────

/// Run the **responder** (Bob) side of the P2P handshake.
///
/// Returns a ready `DoubleRatchetSession` and the initiator's Ed25519 public
/// key bytes.
pub async fn responder_handshake(
    stream: &mut super::transport::FramedStream,
    identity: &IdentityKeyPair,
    bundle: &PreKeyBundle,
    spk_secret: StaticSecret,
    opk_secret: Option<StaticSecret>,
    #[cfg(feature = "pqc")]
    pq_sk: Option<Vec<u8>>,
    protocol_config: Config,
    handshake_cfg: &P2pHandshakeConfig,
    our_device_id: [u8; 16],
) -> P2pResult<(DoubleRatchetSession, [u8; 32])> {
    let timeout = tokio::time::Duration::from_secs(handshake_cfg.timeout_secs);

    tokio::time::timeout(timeout, async {
        // ── 1. Receive Hello (Alice's Ephemeral) ───────────────────────
        let frame = stream.next().await.ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        
        let (alice_ephemeral_pub, initiator_device_id) = match decode_msg(&frame)? {
            P2pMsg::Hello { version, ephemeral_pub, initiator_device_id } => {
                if version != P2P_PROTOCOL_VERSION {
                    return Err(P2pError::Handshake("version mismatch".into()));
                }
                let pub_key = PublicKey::from(ephemeral_pub);
                crate::crypto::validate_public_key(pub_key.as_bytes())
                    .map_err(|_| P2pError::Handshake("invalid initiator ephemeral".into()))?;
                (pub_key, initiator_device_id)
            }
            other => return Err(P2pError::InvalidMessage(format!("expected Hello, got {:?}", other))),
        };

        // ── 2. Send Bundle (Encrypted) ─────────────────────────────────
        let bob_ephemeral = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let bob_ephemeral_pub = PublicKey::from(&bob_ephemeral);

        let handler = derive_handshake_key(&bob_ephemeral, &alice_ephemeral_pub)?;

        let stealth_bundle = StealthBundle {
            responder_ed25519_pub: identity.ed25519_public,
            responder_x25519_pub: identity.x25519_public,
            responder_device_id: our_device_id,
            bundle_bytes: bundle.to_bytes(),
        };
        let bundle_payload = bincode::serialize(&stealth_bundle)
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        let encrypted_bundle = handler.encrypt(&bundle_payload, b"handshake_bundle")
            .map_err(|_| P2pError::Crypto("failed to encrypt bundle".into()))?;

        stream.send(encode_msg(&P2pMsg::Bundle {
            ephemeral_pub: *bob_ephemeral_pub.as_bytes(),
            encrypted_bundle,
        })?).await
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())))?;

        // ── 3. Receive Envelope (Encrypted) ────────────────────────────
        let frame = stream.next().await.ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        
        let encrypted_envelope = match decode_msg(&frame)? {
            P2pMsg::Envelope { encrypted_envelope } => encrypted_envelope,
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => return Err(P2pError::InvalidMessage(format!("expected Envelope, got {:?}", other))),
        };

        let envelope_payload = handler.decrypt(&encrypted_envelope, b"handshake_envelope")
            .map_err(|_| P2pError::Handshake("failed to decrypt envelope".into()))?;
        let stealth_envelope: StealthEnvelope = bincode::deserialize(&envelope_payload)
            .map_err(|e| P2pError::Handshake(format!("malformed stealth envelope: {}", e)))?;

        // ── Transcript Binding (v2.0) ──────────────────────────────────
        let mut hasher = blake3::Hasher::new();
        hasher.update(alice_ephemeral_pub.as_bytes());
        hasher.update(bob_ephemeral_pub.as_bytes());
        hasher.update(&initiator_device_id);
        hasher.update(&our_device_id);
        hasher.update(&stealth_envelope.initiator_ed25519_pub);
        hasher.update(&identity.ed25519_public);
        let transcript_hash = hasher.finalize();

        // ── Run X3DH responder ─────────────────────────────────────────
        let our_identity_x = identity.x25519_secret.as_ref()
            .ok_or_else(|| P2pError::Crypto("identity X25519 secret not available".into()))?;

        let initiator_identity_x = PublicKey::from(stealth_envelope.initiator_x25519_pub);
        let initiator_eph_pub    = PublicKey::from(stealth_envelope.ephemeral_pub);

        #[cfg(feature = "pqc")]
        let x3dh_result = crate::handshake::x3dh::x3dh_responder_v10(
            our_identity_x,
            &spk_secret,
            opk_secret.as_ref(),
            &initiator_identity_x,
            &initiator_eph_pub,
            pq_sk.as_ref(),
            stealth_envelope.pq_ciphertext.as_ref(),
            transcript_hash.as_bytes(),
        ).map_err(|e| P2pError::Handshake(format!("x3dh_responder: {:?}", e)))?;

        #[cfg(not(feature = "pqc"))]
        let x3dh_result = crate::handshake::x3dh::x3dh_responder_v10(
            our_identity_x,
            &spk_secret,
            opk_secret.as_ref(),
            &initiator_identity_x,
            &initiator_eph_pub,
            transcript_hash.as_bytes(),
        ).map_err(|e| P2pError::Handshake(format!("x3dh_responder: {:?}", e)))?;

        // ── 4. Send Ok (Encrypted) ─────────────────────────────────────
        let encrypted_ok = handler.encrypt(b"OK", b"handshake_ok")
            .map_err(|_| P2pError::Crypto("failed to encrypt ok signal".into()))?;

        stream.send(encode_msg(&P2pMsg::Ok {
            encrypted_ok,
        })?).await
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())))?;

        // Build Double Ratchet session
        let mut shared_secret = x3dh_result.shared_secret;
        let session = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            spk_secret,
            initiator_eph_pub,
            protocol_config,
            false,
        ).map_err(|e| P2pError::Crypto(format!("ratchet init: {:?}", e)))?;

        shared_secret.zeroize();

        Ok((session, stealth_envelope.initiator_ed25519_pub))
    })
    .await
    .map_err(|_| P2pError::Timeout)?
}
