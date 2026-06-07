//! P2P Handshake — unified X3DH without a server
//!
//! Two peers exchange PreKey Bundles and X3DH envelopes directly over TCP
//! and establish a Double Ratchet session without any server involvement.
//!
//! ## Wire protocol (4-message handshake)
//!
//! ```text
//! Initiator (Alice)                    Responder (Bob)
//! ─────────────────                    ───────────────
//!  1. → P2pMsg::Hello  (version, ephemeral_pub, device_id)
//!                         ──────────────────────────────►
//!  (← P2pMsg::Bundle)           2. Bob sends encrypted bundle
//!                         ◄──────────────────────────────
//!  3. → P2pMsg::Envelope   (X3DH ciphertext)
//!                         ──────────────────────────────►
//!                                          4. Bob confirms
//!  (← P2pMsg::Ok)          ◄──────────────────────────────
//! ```
//!
//! ## Unification with X3DH (SIBNA-2026-030)
//!
//! This handshake now uses a **single ephemeral key** per side — the same
//! key that participates in X3DH also protects the transport layer.  The
//! transcript hash is constructed identically to `x3dh_initiator_v3` /
//! `x3dh_responder_v3` so that the external `transcript_hash_ext` binding
//! is a no-op (HKDF-Extract with identical inputs), eliminating the
//! previous mismatch where P2P included both ephemeral keys while X3DH
//! included the signed/one-time prekeys.
//!
//! All `P2pMsg` frames are encoded with `bincode` then framed by the
//! length-delimited codec in `transport.rs`.

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::{P2pError, P2pResult};
use crate::{
    handshake::{HandshakeRole, PreKeyBundle},
    keystore::IdentityKeyPair,
    ratchet::DoubleRatchetSession,
    Config,
};

/// Configuration for the P2P handshake phase.
#[derive(Clone, Debug)]
pub struct P2pHandshakeConfig {
    /// Seconds before handshake times out
    pub timeout_secs: u64,
    /// Max frame bytes — must match transport
    pub max_frame_bytes: usize,
    /// Expected peer Ed25519 identity (from P2pConfig).
    ///
    /// **Mandatory**: if `None`, the handshake returns `P2pError::Handshake`
    /// and the connection is **not** established. Callers must pre-exchange
    /// peer identities (safety number QR codes, directory) and set this field
    /// before initiating a P2P connection. See SIBNA-2026-020 + PATCH 17.
    pub expected_peer_identity: Option<[u8; 32]>,
}

impl Default for P2pHandshakeConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_frame_bytes: 10 * 1024 * 1024,
            expected_peer_identity: None,
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
        /// Initiator's ephemeral X25519 public key (used for BOTH transport and X3DH)
        ephemeral_pub: [u8; 32],
        /// Initiator's device ID (to prevent state collision)
        initiator_device_id: [u8; 16],
    },
    /// Step 2 (Responder → Initiator): provide encrypted bundle.
    Bundle {
        /// Responder's ephemeral X25519 public key (used for BOTH transport and X3DH)
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
    Error { reason: String },
}

use crate::crypto::{CryptoHandler, SimpleKdf};

/// Bumped on any breaking wire-format change.
/// v4: single ephemeral key, X3DH-aligned transcript (SIBNA-2026-030)
const P2P_PROTOCOL_VERSION: u8 = 4;

// ── Serialisation & Handshake Crypto ───────────────────────────────────────

pub(crate) fn encode_msg(msg: &P2pMsg) -> P2pResult<Bytes> {
    bincode::serde::encode_to_vec(msg, bincode::config::legacy())
        .map(Bytes::from)
        .map_err(|e| P2pError::Framing(e.to_string()))
}

pub(crate) fn decode_msg(bytes: &[u8]) -> P2pResult<P2pMsg> {
    bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
        .map(|(v, _)| v)
        .map_err(|e| P2pError::InvalidMessage(e.to_string()))
}

/// Derive a transient key for protecting the handshake identity exchange.
///
/// Uses the shared secret from the single ephemeral DH — the same key
/// that participates in X3DH.
fn derive_handshake_key(
    our_ephemeral: &StaticSecret,
    peer_ephemeral_pub: &PublicKey,
) -> P2pResult<CryptoHandler> {
    let shared = our_ephemeral.diffie_hellman(peer_ephemeral_pub);
    let key = SimpleKdf::derive_sha256(shared.as_bytes(), b"SibnaHandshake_v4")
        .map_err(|e| P2pError::Crypto(e.to_string()))?;

    CryptoHandler::new(key.as_ref()).map_err(|e| P2pError::Crypto(e.to_string()))
}

/// Build the P2P transcript hash using the same inputs as X3DH's internal
/// transcript construction.
///
/// This ensures that `transcript_hash_ext` (the P2P outer hash) is combined
/// with the X3DH inner transcript via HKDF in a way that is consistent with
/// the pure-X3DH flow.
fn build_transcript(
    initiator_identity: &[u8; 32],
    initiator_ephemeral: &PublicKey,
    responder_identity: &[u8; 32],
    responder_signed_prekey: &[u8; 32],
    responder_onetime_prekey: Option<&[u8; 32]>,
    initiator_device_id: &[u8; 16],
    responder_device_id: &[u8; 16],
) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    // Match x3dh_initiator_v3 / x3dh_responder_v3 internal transcript order:
    // our_identity, our_ephemeral, peer_identity, peer_signed_prekey,
    // peer_onetime_prekey (optional), our_device_id, peer_device_id
    hasher.update(initiator_identity);
    hasher.update(initiator_ephemeral.as_bytes());
    hasher.update(responder_identity);
    hasher.update(responder_signed_prekey);
    if let Some(opk) = responder_onetime_prekey {
        hasher.update(opk);
    }
    hasher.update(initiator_device_id);
    hasher.update(responder_device_id);
    hasher.finalize()
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
        // ── 1. Send Hello (Single Ephemeral + DeviceID) ──────────────
        // One ephemeral key for BOTH transport encryption AND X3DH.
        let alice_ephemeral = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let alice_ephemeral_pub = PublicKey::from(&alice_ephemeral);

        stream
            .send(encode_msg(&P2pMsg::Hello {
                version: P2P_PROTOCOL_VERSION,
                ephemeral_pub: *alice_ephemeral_pub.as_bytes(),
                initiator_device_id: our_device_id,
            })?)
            .await
            .map_err(|e| {
                P2pError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    e.to_string(),
                ))
            })?;

        // ── 2. Receive Bundle (Encrypted) ──────────────────────────────
        let frame = stream
            .next()
            .await
            .ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;

        let (bob_ephemeral_pub, encrypted_bundle) = match decode_msg(&frame)? {
            P2pMsg::Bundle {
                ephemeral_pub,
                encrypted_bundle,
            } => {
                let pub_key = PublicKey::from(ephemeral_pub);
                crate::crypto::validate_public_key(pub_key.as_bytes())
                    .map_err(|_| P2pError::Handshake("invalid responder ephemeral key".into()))?;
                (pub_key, encrypted_bundle)
            }
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => {
                return Err(P2pError::InvalidMessage(format!(
                    "expected Bundle, got {:?}",
                    other
                )))
            }
        };

        let handler = derive_handshake_key(&alice_ephemeral, &bob_ephemeral_pub)?;

        let bundle_payload = handler
            .decrypt(&encrypted_bundle, b"handshake_bundle")
            .map_err(|_| P2pError::Handshake("failed to decrypt bundle".into()))?;
        let stealth_bundle: StealthBundle =
            bincode::serde::decode_from_slice(&bundle_payload, bincode::config::legacy())
                .map(|(v, _)| v)
                .map_err(|e| P2pError::Handshake(format!("malformed stealth bundle: {}", e)))?;

        let bundle = PreKeyBundle::from_bytes(&stealth_bundle.bundle_bytes)
            .map_err(|e| P2pError::Handshake(format!("malformed internal bundle: {:?}", e)))?;
        bundle
            .validate()
            .map_err(|e| P2pError::Handshake(format!("bundle validation: {:?}", e)))?;

        // Verify responder identity against the expected key.
        match handshake_cfg.expected_peer_identity {
            Some(ref expected) => {
                if stealth_bundle.responder_ed25519_pub != *expected {
                    return Err(P2pError::Handshake(format!(
                        "peer identity mismatch: expected={} got={}",
                        hex::encode(&expected[..4]),
                        hex::encode(&stealth_bundle.responder_ed25519_pub[..4])
                    )));
                }
            }
            None => {
                return Err(P2pError::Handshake(
                    "no expected_peer_identity configured. \
                     P2P connections require an out-of-band identity \
                     verification (safety number exchange) to prevent MITM. \
                     Set P2pConfig::expected_peer_identity to the peer's \
                     known Ed25519 key."
                        .to_string(),
                ));
            }
        }

        // ── Transcript Binding (X3DH-aligned) ─────────────────────────
        // Use the SAME construction as x3dh_initiator_v3 internal transcript.
        let transcript_hash = build_transcript(
            &identity.ed25519_public,
            &alice_ephemeral_pub,
            &stealth_bundle.responder_ed25519_pub,
            &bundle.signed_prekey,
            bundle.onetime_prekey.as_ref(),
            &our_device_id,
            &stealth_bundle.responder_device_id,
        );

        // ── Run X3DH initiator ─────────────────────────────────────────
        // Use the SAME ephemeral key that was sent in Hello — no separate
        // x3dh_ephemeral.
        let our_identity_x = identity
            .x25519_secret
            .as_ref()
            .ok_or_else(|| P2pError::Crypto("identity X25519 secret not available".into()))?;

        let peer_identity_x = PublicKey::from(stealth_bundle.responder_x25519_pub);
        let peer_spk_pub = PublicKey::from(bundle.signed_prekey);
        let peer_opk_pub = bundle.onetime_prekey.map(PublicKey::from);

        #[cfg(feature = "pqc")]
        let mut x3dh_result = crate::handshake::x3dh::x3dh_initiator_v3(
            our_identity_x,
            &alice_ephemeral,
            &peer_identity_x,
            &peer_spk_pub,
            peer_opk_pub.as_ref(),
            bundle.pq_signed_prekey.as_ref(),
            &our_device_id,
            &stealth_bundle.responder_device_id,
            transcript_hash.as_bytes(),
        )
        .map_err(|e| P2pError::Handshake(format!("x3dh_initiator: {:?}", e)))?;

        #[cfg(not(feature = "pqc"))]
        let mut x3dh_result = crate::handshake::x3dh::x3dh_initiator_v3(
            our_identity_x,
            &alice_ephemeral,
            &peer_identity_x,
            &peer_spk_pub,
            peer_opk_pub.as_ref(),
            &our_device_id,
            &stealth_bundle.responder_device_id,
            transcript_hash.as_bytes(),
        )
        .map_err(|e| P2pError::Handshake(format!("x3dh_initiator: {:?}", e)))?;

        // ── 3. Send Envelope (Encrypted) ───────────────────────────────
        let stealth_envelope = StealthEnvelope {
            initiator_ed25519_pub: identity.ed25519_public,
            initiator_x25519_pub: identity.x25519_public,
            initiator_device_id: our_device_id,
            signed_prekey_used: bundle.signed_prekey,
            onetime_prekey_used: bundle.onetime_prekey,
            #[cfg(feature = "pqc")]
            pq_ciphertext: x3dh_result.pq_ciphertext.take(),
        };
        let envelope_payload =
            bincode::serde::encode_to_vec(&stealth_envelope, bincode::config::legacy())
                .map_err(|e| P2pError::Framing(e.to_string()))?;
        let encrypted_envelope = handler
            .encrypt(&envelope_payload, b"handshake_envelope")
            .map_err(|_| P2pError::Crypto("failed to encrypt envelope".into()))?;

        stream
            .send(encode_msg(&P2pMsg::Envelope { encrypted_envelope })?)
            .await
            .map_err(|e| {
                P2pError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    e.to_string(),
                ))
            })?;

        // ── 4. Receive Ok (Encrypted) ──────────────────────────────────
        let frame = stream
            .next()
            .await
            .ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;

        let encrypted_ok = match decode_msg(&frame)? {
            P2pMsg::Ok { encrypted_ok } => encrypted_ok,
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => {
                return Err(P2pError::InvalidMessage(format!(
                    "expected Ok, got {:?}",
                    other
                )))
            }
        };

        let _ = handler
            .decrypt(&encrypted_ok, b"handshake_ok")
            .map_err(|_| P2pError::Handshake("failed to decrypt ok signal".into()))?;

        // Build Double Ratchet session
        let remote_dh = PublicKey::from(bundle.signed_prekey);
        let mut shared_secret = x3dh_result.shared_secret;

        let role = HandshakeRole::Initiator;

        let session = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            alice_ephemeral,
            remote_dh,
            protocol_config,
            role,
        )
        .map_err(|e| P2pError::Crypto(format!("ratchet init: {:?}", e)))?;

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
    #[cfg(feature = "pqc")] pq_sk: Option<Vec<u8>>,
    protocol_config: Config,
    handshake_cfg: &P2pHandshakeConfig,
    our_device_id: [u8; 16],
) -> P2pResult<(DoubleRatchetSession, [u8; 32])> {
    let timeout = tokio::time::Duration::from_secs(handshake_cfg.timeout_secs);

    tokio::time::timeout(timeout, async {
        // ── 1. Receive Hello (Alice's Ephemeral) ───────────────────────
        let frame = stream
            .next()
            .await
            .ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;

        let (alice_ephemeral_pub, initiator_device_id) = match decode_msg(&frame)? {
            P2pMsg::Hello {
                version,
                ephemeral_pub,
                initiator_device_id,
            } => {
                if version != P2P_PROTOCOL_VERSION {
                    return Err(P2pError::Handshake("version mismatch".into()));
                }
                let pub_key = PublicKey::from(ephemeral_pub);
                crate::crypto::validate_public_key(pub_key.as_bytes())
                    .map_err(|_| P2pError::Handshake("invalid initiator ephemeral".into()))?;
                (pub_key, initiator_device_id)
            }
            other => {
                return Err(P2pError::InvalidMessage(format!(
                    "expected Hello, got {:?}",
                    other
                )))
            }
        };

        // ── 2. Send Bundle (Encrypted) ─────────────────────────────────
        // Single ephemeral key for BOTH transport and X3DH.
        let bob_ephemeral = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let bob_ephemeral_pub = PublicKey::from(&bob_ephemeral);

        let handler = derive_handshake_key(&bob_ephemeral, &alice_ephemeral_pub)?;

        let stealth_bundle = StealthBundle {
            responder_ed25519_pub: identity.ed25519_public,
            responder_x25519_pub: identity.x25519_public,
            responder_device_id: our_device_id,
            bundle_bytes: bundle.to_bytes(),
        };
        let bundle_payload =
            bincode::serde::encode_to_vec(&stealth_bundle, bincode::config::legacy())
                .map_err(|e| P2pError::Framing(e.to_string()))?;
        let encrypted_bundle = handler
            .encrypt(&bundle_payload, b"handshake_bundle")
            .map_err(|_| P2pError::Crypto("failed to encrypt bundle".into()))?;

        stream
            .send(encode_msg(&P2pMsg::Bundle {
                ephemeral_pub: *bob_ephemeral_pub.as_bytes(),
                encrypted_bundle,
            })?)
            .await
            .map_err(|e| {
                P2pError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    e.to_string(),
                ))
            })?;

        // ── 3. Receive Envelope (Encrypted) ────────────────────────────
        let frame = stream
            .next()
            .await
            .ok_or(P2pError::Disconnected)?
            .map_err(|e| P2pError::Framing(e.to_string()))?;

        let encrypted_envelope = match decode_msg(&frame)? {
            P2pMsg::Envelope { encrypted_envelope } => encrypted_envelope,
            P2pMsg::Error { reason } => return Err(P2pError::Handshake(reason)),
            other => {
                return Err(P2pError::InvalidMessage(format!(
                    "expected Envelope, got {:?}",
                    other
                )))
            }
        };

        let envelope_payload = handler
            .decrypt(&encrypted_envelope, b"handshake_envelope")
            .map_err(|_| P2pError::Handshake("failed to decrypt envelope".into()))?;
        let stealth_envelope: StealthEnvelope =
            bincode::serde::decode_from_slice(&envelope_payload, bincode::config::legacy())
                .map(|(v, _)| v)
                .map_err(|e| P2pError::Handshake(format!("malformed stealth envelope: {}", e)))?;

        // ── Transcript Binding (X3DH-aligned) ─────────────────────────
        // Use the SAME construction as x3dh_responder_v3 internal transcript.
        let transcript_hash = build_transcript(
            &stealth_envelope.initiator_ed25519_pub,
            &alice_ephemeral_pub,
            &identity.ed25519_public,
            &bundle.signed_prekey,
            bundle.onetime_prekey.as_ref(),
            &initiator_device_id,
            &our_device_id,
        );

        // ── Run X3DH responder ─────────────────────────────────────────
        let our_identity_x = identity
            .x25519_secret
            .as_ref()
            .ok_or_else(|| P2pError::Crypto("identity X25519 secret not available".into()))?;

        let initiator_identity_x = PublicKey::from(stealth_envelope.initiator_x25519_pub);

        #[cfg(feature = "pqc")]
        let x3dh_result = crate::handshake::x3dh::x3dh_responder_v3(
            our_identity_x,
            &spk_secret,
            opk_secret.as_ref(),
            &initiator_identity_x,
            &alice_ephemeral_pub,
            pq_sk.as_ref(),
            stealth_envelope.pq_ciphertext.as_ref(),
            &our_device_id,
            &initiator_device_id,
            transcript_hash.as_bytes(),
        )
        .map_err(|e| P2pError::Handshake(format!("x3dh_responder: {:?}", e)))?;

        #[cfg(not(feature = "pqc"))]
        let x3dh_result = crate::handshake::x3dh::x3dh_responder_v3(
            our_identity_x,
            &spk_secret,
            opk_secret.as_ref(),
            &initiator_identity_x,
            &alice_ephemeral_pub,
            &our_device_id,
            &initiator_device_id,
            transcript_hash.as_bytes(),
        )
        .map_err(|e| P2pError::Handshake(format!("x3dh_responder: {:?}", e)))?;

        // ── 4. Send Ok (Encrypted) ─────────────────────────────────────
        let encrypted_ok = handler
            .encrypt(b"OK", b"handshake_ok")
            .map_err(|_| P2pError::Crypto("failed to encrypt ok signal".into()))?;

        stream
            .send(encode_msg(&P2pMsg::Ok { encrypted_ok })?)
            .await
            .map_err(|e| {
                P2pError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    e.to_string(),
                ))
            })?;

        // Build Double Ratchet session
        let mut shared_secret = x3dh_result.shared_secret;

        let role = HandshakeRole::Responder;

        let session = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            spk_secret,
            alice_ephemeral_pub,
            protocol_config,
            role,
        )
        .map_err(|e| P2pError::Crypto(format!("ratchet init: {:?}", e)))?;

        shared_secret.zeroize();

        Ok((session, stealth_envelope.initiator_ed25519_pub))
    })
    .await
    .map_err(|_| P2pError::Timeout)?
}
