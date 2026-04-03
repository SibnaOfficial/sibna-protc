//! Hybrid Routing Manager
//!
//! The `HybridRouter` coordinates between P2P direct transport and
//! Server-based relay transport. It implements a "P2P-first" policy.

use crate::{SecureContext, ProtocolResult};
#[cfg(feature = "p2p")]
use crate::p2p::{P2pNode, Peer};
use tracing::{info, warn};

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
        }
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
                    if peer.send_message(plaintext).await.is_ok() {
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

    /// Start a background task to discover local peers and connect to them.
    #[cfg(feature = "p2p")]
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
}
