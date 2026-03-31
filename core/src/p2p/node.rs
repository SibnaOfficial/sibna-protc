//! Top-level P2P node — bind, connect, accept
//!
//! `P2pNode` is the main entry point for the P2P transport layer.
//! It owns the TCP listener, the `SecureContext`, and a live `PreKeyBundle`
//! that it hands to connecting peers during the P2P handshake.

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use x25519_dalek::StaticSecret;

use crate::{
    SecureContext,
    keystore::SignedPreKey,
    handshake::PreKeyBundle,
};
use super::{
    P2pConfig, P2pError, P2pResult,
    handshake::{P2pHandshakeConfig, initiator_handshake, responder_handshake},
    peer::Peer,
    transport,
};

/// Top-level P2P node.
///
/// Create one per process / application instance. Call `connect` to dial a
/// remote peer, or `accept` to wait for an incoming connection. Both return a
/// ready-to-use [`Peer`] with a fully established Double Ratchet session.
pub struct P2pNode {
    /// The local TCP listener
    listener: TcpListener,
    /// Secure context for handshake/crypto
    ctx: Arc<SecureContext>,
    #[allow(dead_code)]
    identity: [u8; 32],
    /// Our published prekey bundle
    bundle: PreKeyBundle,
    /// Our signed prekey secret (needed for responder handshake)
    spk_secret: StaticSecret,
    /// Our PQ signed prekey secret (needed for responder handshake)
    #[cfg(feature = "pqc")]
    pq_sk: Option<Vec<u8>>,
    /// Handshake configuration derived from `P2pConfig`
    hs_cfg: P2pHandshakeConfig,
    /// Optional mDNS discovery module
    discovery: Option<super::discovery::MdnsDiscovery>,
    /// Optional NAT traversal manager
    nat: Option<super::nat::NatManager>,
    /// Configuration
    config: P2pConfig,
}

impl P2pNode {
    /// Create a new P2P node: generate fresh prekeys, bind the TCP listener,
    /// and return a ready-to-use node.
    ///
    /// # Arguments
    /// * `config` — P2P configuration (bind address, timeouts, limits)
    /// * `ctx` — an already-initialised `SecureContext` **with an identity key**.
    ///   Call `ctx.generate_identity()` before passing it here if needed.
    ///
    /// # Errors
    /// - `P2pError::Io` — cannot bind TCP listener
    /// - `P2pError::Crypto` — identity key missing or prekey generation failed
    pub async fn new(config: P2pConfig, ctx: SecureContext) -> P2pResult<Self> {
        let ctx = Arc::new(ctx);

        // Make sure the SecureContext has an identity key.
        let identity = ctx.get_identity()
            .map_err(|e| P2pError::Crypto(format!("get_identity: {:?}", e)))?;

        // Generate a fresh signed prekey and one OPK for this node's lifetime.
        let spk = SignedPreKey::generate(1, &identity)
            .map_err(|e| P2pError::Crypto(format!("gen spk: {:?}", e)))?;
        let spk_public = spk.public;
        let spk_secret = spk.secret.clone()
            .ok_or_else(|| P2pError::Crypto("spk secret not available".into()))?;
        
        #[cfg(feature = "pqc")]
        let pq_sk = spk.pq_secret;
        #[cfg(feature = "pqc")]
        let pq_pk = spk.pq_public;
        let spk_sig: [u8; 64] = spk.signature.as_slice()
            .try_into()
            .map_err(|_| P2pError::Crypto("bad spk signature length".into()))?;

        // Build the device-linking payload (self-signed as master device)
        let device_link_payload = {
            let mut p = Vec::with_capacity(36);
            p.extend_from_slice(&identity.ed25519_public);
            p.extend_from_slice(&0u32.to_le_bytes());
            p
        };
        let device_sig = identity
            .sign(&device_link_payload)
            .map_err(|e| P2pError::Crypto(format!("sign device: {:?}", e)))?;

        // Build our bundle (master device, no OPK for simplicity)
        let mut bundle = PreKeyBundle::new(
            identity.ed25519_public,
            spk_public,
            spk_sig,
            None,                      // no one-time prekey in P2P mode
            0,                         // device_id = 0 (master)
            identity.ed25519_public,   // root key = self for standalone node
            device_sig,
        );

        #[cfg(feature = "pqc")]
        if let Some(pk) = pq_pk {
            let pq_sig = identity.sign(&pk)
                .map_err(|e| P2pError::Crypto(format!("sign pq prekey: {:?}", e)))?;
            bundle = bundle.with_pq_prekey(pk, pq_sig);
        }

        // Sign the full bundle.
        bundle.sign_bundle(|data| {
            identity.sign(data)
                .map_err(|e| {
                    crate::error::ProtocolError::InternalErrorDetailed {
                        details: format!("bundle sign: {:?}", e)
                    }
                })
        }).map_err(|e| P2pError::Crypto(format!("sign_bundle: {:?}", e)))?;

        // Bind the TCP listener.
        let listener = transport::listen(config.bind_addr)
            .await?;

        let hs_cfg = P2pHandshakeConfig {
            timeout_secs: config.handshake_timeout_secs,
            max_frame_bytes: config.max_message_size,
        };

        // Initialize NAT traversal if enabled
        let nat = if config.enable_mdns {
            Some(super::nat::NatManager::new(listener.local_addr()?.port()).await)
        } else {
            None
        };

        // Initialize mDNS discovery if enabled.
        let discovery = if config.enable_mdns {
            let mut discover_addr = listener.local_addr().unwrap_or(config.bind_addr);
            
            // If we found a public address via NAT traversal, prefer it for broad reachability
            if let Some(ref n) = nat {
                if let Some(pub_addr) = n.public_addr {
                    discover_addr = pub_addr;
                }
            }

            Some(super::discovery::MdnsDiscovery::new(
                discover_addr,
                &identity.ed25519_public,
                config.node_name.as_deref()
            )?)
        } else {
            None
        };

        Ok(Self {
            listener,
            ctx,
            identity: identity.ed25519_public,
            bundle,
            spk_secret,
            #[cfg(feature = "pqc")]
            pq_sk,
            hs_cfg,
            discovery,
            nat,
            config,
        })
    }

    /// Return the local socket address this node is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().expect("listener has addr")
    }

    /// Export this node's `PreKeyBundle` as bytes.
    pub fn export_bundle(&self) -> Vec<u8> {
        self.bundle.to_bytes()
    }

    /// Browse the local network for other active P2P nodes.
    pub fn browse_peers(&self) -> P2pResult<tokio::sync::mpsc::Receiver<super::discovery::DiscoveredPeer>> {
        if let Some(ref d) = self.discovery {
            d.browse_peers()
        } else {
            Err(P2pError::InvalidMessage("mDNS is not enabled on this node".to_string()))
        }
    }

    /// Returns the discovered public address if NAT traversal was successful.
    pub fn public_addr(&self) -> Option<SocketAddr> {
        self.nat.as_ref().and_then(|n| n.public_addr)
    }

    /// Parse and validate an externally-supplied `PreKeyBundle`.
    pub fn import_bundle(bytes: &[u8]) -> P2pResult<PreKeyBundle> {
        let bundle = PreKeyBundle::from_bytes(bytes)
            .map_err(|e| P2pError::InvalidMessage(format!("malformed bundle: {:?}", e)))?;
        bundle.validate()
            .map_err(|e| P2pError::Handshake(format!("bundle invalid: {:?}", e)))?;
        Ok(bundle)
    }

    /// Dial `addr` and perform the P2P X3DH handshake as **initiator**.
    pub async fn connect(&self, addr: &str) -> P2pResult<Peer> {
        let mut stream = transport::connect(addr, self.hs_cfg.max_frame_bytes).await?;
        let remote_addr: SocketAddr = addr.parse()
            .map_err(|_| P2pError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "invalid address",
            )))?;

        let identity = self.ctx.get_identity()
            .map_err(|e| P2pError::Crypto(format!("get_identity: {:?}", e)))?;

        let protocol_cfg = self.ctx.config().clone();

        let (session, peer_id) = initiator_handshake(
            &mut stream,
            &identity,
            protocol_cfg,
            &self.hs_cfg,
        ).await?;

        Ok(Peer::new(peer_id, stream, session, remote_addr))
    }

    /// Wait for an incoming connection and perform the P2P X3DH handshake as **responder**.
    pub async fn accept(&self) -> P2pResult<Peer> {
        let (mut stream, remote_addr) = transport::accept(&self.listener, self.hs_cfg.max_frame_bytes).await?;

        let identity = self.ctx.get_identity()
            .map_err(|e| P2pError::Crypto(format!("get_identity: {:?}", e)))?;

        let protocol_cfg = self.ctx.config().clone();
        let spk_secret_clone = clone_static_secret(&self.spk_secret);

        let (session, peer_id) = responder_handshake(
            &mut stream,
            &identity,
            &self.bundle,
            spk_secret_clone,
            None, // no OPK
            #[cfg(feature = "pqc")]
            self.pq_sk.clone(),
            protocol_cfg,
            &self.hs_cfg,
        ).await?;

        Ok(Peer::new(peer_id, stream, session, remote_addr))
    }
}

fn clone_static_secret(s: &StaticSecret) -> StaticSecret {
    StaticSecret::from(*s.as_bytes())
}

impl std::fmt::Debug for P2pNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pNode")
            .field("local_addr", &self.local_addr())
            .field("max_peers", &self.config.max_peers)
            .finish()
    }
}
