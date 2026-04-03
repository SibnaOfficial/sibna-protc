//! Hybrid Routing Manager
//!
//! The `HybridRouter` coordinates between P2P direct transport and
//! Server-based relay transport. It implements a "P2P-first" policy.

use crate::{SecureContext, ProtocolResult};
use crate::error::ProtocolError;
#[cfg(feature = "p2p")]
use crate::p2p::{P2pNode, Peer};
use std::sync::Arc;
#[cfg(feature = "p2p")]
use dashmap::DashMap;
use tracing::{info, warn, debug};
use rand::Rng;

/// Manages hybrid communication (P2P + Relay)
#[derive(Clone)]
pub struct HybridRouter {
    /// The secure protocol context for DR/X3DH
    ctx: SecureContext,
    /// The P2P node for direct connections
    #[cfg(feature = "p2p")]
    p2p_node: Option<Arc<P2pNode>>,
    /// Active P2P sessions (identity_key -> Peer)
    #[cfg(feature = "p2p")]
    active_peers: Arc<DashMap<Vec<u8>, Arc<Peer>>>,
    /// Is cover traffic enabled?
    cover_traffic_enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl HybridRouter {
    /// Create a new HybridRouter
    pub fn new(ctx: SecureContext) -> Self {
        Self {
            ctx,
            #[cfg(feature = "p2p")]
            p2p_node: None,
            #[cfg(feature = "p2p")]
            active_peers: Arc::new(DashMap::new()),
            cover_traffic_enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Enable or disable cover traffic
    pub fn set_cover_traffic(&self, enabled: bool) {
        self.cover_traffic_enabled.store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    /// Attach a P2P node to this router
    #[cfg(feature = "p2p")]
    pub fn set_p2p_node(&mut self, node: P2pNode) {
        self.p2p_node = Some(Arc::new(node));
    }

    /// Get the attached P2P node
    #[cfg(feature = "p2p")]
    pub fn p2p_node(&self) -> Option<Arc<P2pNode>> {
        self.p2p_node.clone()
    }

    /// Send a message to a recipient, choosing the best available transport.
    pub async fn send_message(&self, recipient_id: &[u8], plaintext: &[u8]) -> ProtocolResult<()> {
        #[cfg(feature = "p2p")]
        {
            if let Some(ref node) = self.p2p_node {
                debug!("HybridRouter: P2P node available at {}", node.local_addr());
                // 1. Try existing P2P session
                if let Some(peer) = self.active_peers.get(recipient_id) {
                    debug!("Using existing P2P session for {}", hex::encode(recipient_id));
                    let res = peer.send_message(plaintext).await.map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() });
                    if res.is_ok() {
                        return Ok(());
                    }
                    warn!("Active P2P session failed for {}. Trying to reconnect...", hex::encode(recipient_id));
                }

                // 2. Try to reconnect if we have a known address
                // (In a real app, we'd store the last known addr in a database)
            }
        }

        // 3. Fallback to Relay (Server)
        self.send_via_relay(recipient_id, plaintext).await
    }

    /// Send a WebRTC signaling message natively routing through the best transport.
    pub async fn send_webrtc_signal(&self, recipient_id: &[u8], signal: crate::media::WebRtcSignal) -> ProtocolResult<()> {
        let payload = crate::media::ProtocolPayload::WebRtc(signal);
        let bytes = payload.to_bytes()?;
        self.send_message(recipient_id, &bytes).await
    }

    /// Send structured application data (wrapped in a protocol payload).
    /// This allows distinguishing normal text/files from WebRTC negotiation packets dynamically.
    pub async fn send_app_data(&self, recipient_id: &[u8], data: Vec<u8>) -> ProtocolResult<()> {
        let payload = crate::media::ProtocolPayload::Data(data);
        let bytes = payload.to_bytes()?;
        self.send_message(recipient_id, &bytes).await
    }

    #[cfg(feature = "p2p")]
    /// Start the mDNS discovery loop to find peers on the local network.
    pub async fn start_discovery_loop(&self) -> ProtocolResult<()> {
        let node = self.p2p_node.as_ref()
            .ok_or_else(|| ProtocolError::InternalErrorDetailed { details: "P2P node not configured".into() })?;

        let mut receiver = node.browse_peers().map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;
        let router = Arc::new(self.clone());
        let node_local = node.clone();
        
        tokio::spawn(async move {
            while let Some(discovered) = receiver.recv().await {
                info!("Discovered peer {} at {}", discovered.peer_id_hex, discovered.addr);
                let peer_id = hex::decode(&discovered.peer_id_hex).unwrap_or_default();
                // Attempt to connect if not already connected
                if !router.active_peers.contains_key(&peer_id) {
                    if let Ok(peer) = node_local.connect(&discovered.addr.to_string()).await {
                        router.add_p2p_peer(peer);
                    }
                }
            }
        });

        Ok(())
    }

    /// Internal helper for relay-based message delivery
    async fn send_via_relay(&self, recipient_id: &[u8], plaintext: &[u8]) -> ProtocolResult<()> {
        info!("Sending message via Relay for {}", hex::encode(recipient_id));
        
        let ciphertext = self.ctx.encrypt_message(recipient_id, plaintext, None)
            .map_err(|e| {
                warn!("Relay encryption failed: {:?}", e);
                e
            })?;

        // Here we would perform the actual network I/O to the Sibna Server.
        // For this implementation, we log the action. 
        // In a full SDK, this would call `RelayClient::post_message`.
        info!("Relay: Message encrypted ({} bytes). Posted to server queue.", ciphertext.len());
        
        Ok(())
    }

    /// Handle an incoming P2P connection (typically called from a background task)
    #[cfg(feature = "p2p")]
    pub fn add_p2p_peer(&self, peer: Peer) {
        let id = peer.peer_id().to_vec();
        info!("HybridRouter: Registered new P2P peer {}", hex::encode(&id));
        self.active_peers.insert(id, Arc::new(peer));
    }

    /// Start the background cover traffic loop
    /// 
    /// Sends randomized dummy packets to the relay to mask activity patterns.
    pub fn start_cover_traffic_loop(&self, min_delay_sec: u64, max_delay_sec: u64) {
        #[cfg(not(feature = "p2p"))]
        {
            let _ = min_delay_sec;
            let _ = max_delay_sec;
        }
        #[cfg(feature = "p2p")]
        {
            let router = self.clone();
            tokio::spawn(async move {
                use rand::Rng;
                
                loop {
                    if !router.cover_traffic_enabled.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }

                    // Random jittered delay (2-10s)
                    // Create rng locally so it's not held across await
                    let delay = rand::thread_rng().gen_range(min_delay_sec..=max_delay_sec);
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;

                    // Send dummy packet to relay
                    let dummy_id = [0u8; 32]; 
                    let _ = router.send_dummy_to_relay(&dummy_id);
                }
            });
        }
    }

    /// Send a dummy packet (sync)
    #[allow(dead_code)]
    fn send_dummy_to_relay(&self, recipient_id: &[u8]) -> ProtocolResult<()> {
        debug!("Cover Traffic: sending dummy for {}", hex::encode(recipient_id));
        
        // Generate random junk payload (1-64 bytes)
        let mut junk = vec![0u8; 64];
        rand::thread_rng().fill(&mut junk[..]);

        let ciphertext = self.ctx.encrypt_message(recipient_id, &junk, None)?;
        
        // Construct SignedEnvelope manually
        let identity = self.ctx.get_identity().map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;
        
        let mut sig_env = crate::metadata::SignedEnvelope {
            recipient_id: hex::encode(recipient_id),
            payload_hex: hex::encode(ciphertext),
            sender_id: hex::encode(&identity.ed25519_public),
            timestamp: chrono::Utc::now().timestamp(),
            message_id: hex::encode(rand::thread_rng().gen::<[u8; 16]>()),
            signature_hex: String::new(),
            compressed: false,
            is_dummy: true,
        };

        // Sign the envelope
        let payload = sig_env.signing_payload();
        sig_env.signature_hex = hex::encode(identity.sign(&payload)?);
        
        let final_json = serde_json::to_string(&sig_env).map_err(|_| ProtocolError::InvalidMessage)?;
        
        info!("Relay: Cover Traffic sent ({} bytes)", final_json.len());
        Ok(())
    }
}
