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

use crate::{
    handshake::{PreKeyBundle, x3dh::x3dh_initiator, x3dh::x3dh_responder},
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

// ── Wire messages ──────────────────────────────────────────────────────────

/// All messages exchanged during a P2P handshake. Encoded with `bincode`.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum P2pMsg {
    /// Step 1 (Initiator → Responder): announce identity and protocol version.
    Hello {
        /// Protocol wire version byte (must be `P2P_PROTOCOL_VERSION`)
        version: u8,
        /// Initiator's Ed25519 public key (32 bytes; used as peer identity ID)
        ed25519_pub: [u8; 32],
        /// Initiator's X25519 public key (32 bytes; used in X3DH DH operations)
        x25519_pub: [u8; 32],
    },
    Bundle {
        /// Serialised `PreKeyBundle::to_bytes()` bytes
        bundle_bytes: Vec<u8>,
        /// Responder's X25519 identity key (needed for X3DH DH derivation)
        responder_x25519_pub: [u8; 32],
    },
    /// Step 3 (Initiator → Responder): provide ephemeral key so responder can
    /// independently compute the same X3DH shared secret.
    Envelope {
        /// Initiator's Ed25519 public key (used as peer identity ID)
        initiator_ed25519_pub: [u8; 32],
        /// Initiator's X25519 public key (used in DH operations)
        initiator_x25519_pub: [u8; 32],
        /// Fresh ephemeral X25519 public key generated for this handshake
        ephemeral_pub: [u8; 32],
        /// The signed prekey the initiator used (so responder can look it up)
        signed_prekey_used: [u8; 32],
        /// One-time prekey used, if any
        onetime_prekey_used: Option<[u8; 32]>,
        /// Post-Quantum Ciphertext (ML-KEM-768)
        #[cfg(feature = "pqc")]
        pq_ciphertext: Option<Vec<u8>>,
    },
    /// Step 4 (Responder → Initiator): confirm that handshake is complete.
    Ok {
        /// Responder's Ed25519 public key (for verification)
        responder_ed25519_pub: [u8; 32],
    },
    /// Either side may send this to signal an abnormal termination.
    Error {
        /// Human-readable reason (not sensitive)
        reason: String,
    },
}

/// Bumped on any breaking wire-format change.
const P2P_PROTOCOL_VERSION: u8 = 1;

// ── Serialisation helpers ──────────────────────────────────────────────────

pub(crate) fn encode_msg(msg: &P2pMsg) -> P2pResult<Bytes> {
    bincode::serialize(msg)
        .map(Bytes::from)
        .map_err(|e| P2pError::Framing(e.to_string()))
}

pub(crate) fn decode_msg(bytes: &[u8]) -> P2pResult<P2pMsg> {
    bincode::deserialize(bytes)
        .map_err(|e| P2pError::InvalidMessage(e.to_string()))
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
) -> P2pResult<(DoubleRatchetSession, [u8; 32])> {
    let timeout = tokio::time::Duration::from_secs(handshake_cfg.timeout_secs);

    // Extract our own X25519 public key
    let our_x25519_pub: [u8; 32] = identity.x25519_public;

    tokio::time::timeout(timeout, async {
        // ── 1. Send Hello ──────────────────────────────────────────────
        stream.send(encode_msg(&P2pMsg::Hello {
            version: P2P_PROTOCOL_VERSION,
            ed25519_pub: identity.ed25519_public,
            x25519_pub: our_x25519_pub,
        })?).await
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())))?;

        // ── 2. Receive Bundle ──────────────────────────────────────────
        let frame = stream.next().await.ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        let (bundle_bytes, responder_x25519_pub) = match decode_msg(&frame)? {
            P2pMsg::Bundle { bundle_bytes, responder_x25519_pub } => (bundle_bytes, responder_x25519_pub),
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => return Err(P2pError::InvalidMessage(format!("expected Bundle, got {:?}", other))),
        };

        let bundle = PreKeyBundle::from_bytes(&bundle_bytes)
            .map_err(|e| P2pError::Handshake(format!("malformed bundle: {:?}", e)))?;
        bundle.validate()
            .map_err(|e| P2pError::Handshake(format!("bundle validation: {:?}", e)))?;

        // ── Run X3DH initiator ─────────────────────────────────────────
        // Generate a fresh ephemeral key pair for this handshake session
        let ephemeral = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let ephemeral_pub = PublicKey::from(&ephemeral);

        // Our identity X25519 static secret
        let our_identity_x = identity.x25519_secret.clone()
            .ok_or_else(|| P2pError::Crypto("identity X25519 secret not available".into()))?;

        // The responder specifically sends their X25519 identity key alongside the bundle
        let peer_identity_x = PublicKey::from(responder_x25519_pub);
        let peer_spk_pub    = PublicKey::from(bundle.signed_prekey);
        let peer_opk_pub    = bundle.onetime_prekey.map(PublicKey::from);

        #[cfg(feature = "pqc")]
        let mut x3dh_result = x3dh_initiator(
            &our_identity_x,
            &ephemeral,
            &peer_identity_x,
            &peer_spk_pub,
            peer_opk_pub.as_ref(),
            bundle.pq_signed_prekey.as_ref(),
        ).map_err(|e| P2pError::Handshake(format!("x3dh_initiator: {:?}", e)))?;

        #[cfg(not(feature = "pqc"))]
        let mut x3dh_result = x3dh_initiator(
            &our_identity_x,
            &ephemeral,
            &peer_identity_x,
            &peer_spk_pub,
            peer_opk_pub.as_ref(),
        ).map_err(|e| P2pError::Handshake(format!("x3dh_initiator: {:?}", e)))?;

        let shared = x3dh_result.shared_secret;

        // ── 3. Send Envelope ───────────────────────────────────────────
        stream.send(encode_msg(&P2pMsg::Envelope {
            initiator_ed25519_pub: identity.ed25519_public,
            initiator_x25519_pub: our_x25519_pub,
            ephemeral_pub: *ephemeral_pub.as_bytes(),
            signed_prekey_used: bundle.signed_prekey,
            onetime_prekey_used: bundle.onetime_prekey,
            #[cfg(feature = "pqc")]
            pq_ciphertext: x3dh_result.pq_ciphertext.take(),
        })?).await
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())))?;

        // ── 4. Receive Ok ──────────────────────────────────────────────
        let frame = stream.next().await.ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        let responder_ed25519_pub = match decode_msg(&frame)? {
            P2pMsg::Ok { responder_ed25519_pub } => responder_ed25519_pub,
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => return Err(P2pError::InvalidMessage(format!("expected Ok, got {:?}", other))),
        };

        // Build Double Ratchet session (initiator role)
        let remote_dh = PublicKey::from(bundle.signed_prekey);
        let session = DoubleRatchetSession::from_shared_secret(
            &shared,
            ephemeral,             // local DH secret
            remote_dh,             // remote DH public
            protocol_config,
            true,                  // initiator
        ).map_err(|e| P2pError::Crypto(format!("ratchet init: {:?}", e)))?;

        Ok((session, responder_ed25519_pub))
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
) -> P2pResult<(DoubleRatchetSession, [u8; 32])> {
    let timeout = tokio::time::Duration::from_secs(handshake_cfg.timeout_secs);

    tokio::time::timeout(timeout, async {
        // ── 1. Receive Hello ───────────────────────────────────────────
        let frame = stream.next().await.ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        let (initiator_ed25519_pub, initiator_x25519_pub) = match decode_msg(&frame)? {
            P2pMsg::Hello { version, ed25519_pub, x25519_pub } => {
                if version != P2P_PROTOCOL_VERSION {
                    let _ = stream.send(encode_msg(&P2pMsg::Error {
                        reason: format!(
                            "version mismatch: peer={}, us={}",
                            version, P2P_PROTOCOL_VERSION
                        ),
                    })?).await;
                    return Err(P2pError::Handshake("protocol version mismatch".into()));
                }
                (ed25519_pub, x25519_pub)
            }
            other => return Err(P2pError::InvalidMessage(format!("expected Hello, got {:?}", other))),
        };

        // ── 2. Send Bundle ─────────────────────────────────────────────
        stream.send(encode_msg(&P2pMsg::Bundle {
            bundle_bytes: bundle.to_bytes(),
            responder_x25519_pub: identity.x25519_public,
        })?).await
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())))?;

        // ── 3. Receive Envelope ────────────────────────────────────────
        let frame = stream.next().await.ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;
        let (ephemeral_pub_bytes, pq_ct) = match decode_msg(&frame)? {
            #[cfg(feature = "pqc")]
            P2pMsg::Envelope { ephemeral_pub, pq_ciphertext, .. } => (ephemeral_pub, pq_ciphertext),
            #[cfg(not(feature = "pqc"))]
            P2pMsg::Envelope { ephemeral_pub, .. } => (ephemeral_pub, None),
            
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => return Err(P2pError::InvalidMessage(format!("expected Envelope, got {:?}", other))),
        };

        // ── Run X3DH responder ─────────────────────────────────────────
        // Our identity X25519 static secret
        let our_identity_x = identity.x25519_secret.clone()
            .ok_or_else(|| P2pError::Crypto("identity X25519 secret not available".into()))?;

        // Initiator's X25519 identity public key (announced in Hello)
        let initiator_identity_x = PublicKey::from(initiator_x25519_pub);
        let initiator_eph_pub    = PublicKey::from(ephemeral_pub_bytes);

        #[cfg(feature = "pqc")]
        let x3dh_result = x3dh_responder(
            &our_identity_x,
            &spk_secret,
            opk_secret.as_ref(),
            &initiator_identity_x,
            &initiator_eph_pub,
            pq_sk.as_ref(),
            pq_ct.as_ref(),
        ).map_err(|e| P2pError::Handshake(format!("x3dh_responder: {:?}", e)))?;

        #[cfg(not(feature = "pqc"))]
        let x3dh_result = x3dh_responder(
            &our_identity_x,
            &spk_secret,
            opk_secret.as_ref(),
            &initiator_identity_x,
            &initiator_eph_pub,
        ).map_err(|e| P2pError::Handshake(format!("x3dh_responder: {:?}", e)))?;

        let shared = x3dh_result.shared_secret;

        // ── 4. Send Ok ─────────────────────────────────────────────────
        stream.send(encode_msg(&P2pMsg::Ok {
            responder_ed25519_pub: identity.ed25519_public,
        })?).await
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())))?;

        // Build Double Ratchet session (responder role)
        let session = DoubleRatchetSession::from_shared_secret(
            &shared,
            spk_secret,              // local DH secret
            initiator_eph_pub,       // remote DH public
            protocol_config,
            false,                   // responder
        ).map_err(|e| P2pError::Crypto(format!("ratchet init: {:?}", e)))?;

        let _ = initiator_ed25519_pub; // used as peer ID below
        Ok((session, initiator_ed25519_pub))
    })
    .await
    .map_err(|_| P2pError::Timeout)?
}
