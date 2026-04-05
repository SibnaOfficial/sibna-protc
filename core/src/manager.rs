//! Hybrid Routing Manager
//!
//! The `HybridRouter` coordinates between P2P direct transport and
//! Server-based relay transport. It implements a "P2P-first" policy.
//!
//! # Security Fixes Applied (Audit v1.0)
//!
//! | ID  | Severity | Description                                              |
//! |-----|----------|----------------------------------------------------------|
//! | F-01| CRITICAL | Race condition in discovery → DashMap entry API          |
//! | F-02| CRITICAL | `unwrap_or_default()` on hex decode → ghost-peer DoS     |
//! | F-03| HIGH     | No peer cap in `add_p2p_peer` → memory exhaustion DoS    |
//! | F-04| HIGH     | `InternalErrorDetailed` leaks internal details to caller |
//! | F-05| HIGH     | Discovery loop has no graceful shutdown/cancellation     |
//! | F-06| MEDIUM   | No input size guard on `send_message`                    |
//! | F-07| MEDIUM   | No peer-address validation before connecting             |
//! | F-08| MEDIUM   | Cover-traffic delay uses uniform distribution            |
//!
//! NOTE on original finding #3 (Signature Verification):
//! The `is_dummy` field IS already included in `signing_payload()` in
//! `metadata.rs` (line 121: `hasher.update(&[self.is_dummy as u8])`).
//! This was a FALSE POSITIVE in the original report. Verified and documented.

use crate::{SecureContext, ProtocolResult};
use crate::error::ProtocolError;
#[cfg(feature = "p2p")]
use crate::p2p::{P2pNode, Peer};
use std::sync::Arc;
#[cfg(feature = "p2p")]
use dashmap::DashMap;
use tracing::{info, warn, debug};
use rand::Rng;

// ── Security constants ────────────────────────────────────────────────────────

/// Maximum number of active P2P peers.
/// Prevents memory exhaustion via mDNS flood attacks. (FIX F-03)
#[cfg(feature = "p2p")]
const MAX_ACTIVE_PEERS: usize = 500;

/// Maximum plaintext size accepted by `send_message`.
/// 64 MiB — prevents gigabyte-sized allocation attacks. (FIX F-06)
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Mean delay (seconds) for exponential cover-traffic distribution. (FIX F-08)
#[cfg(feature = "p2p")]
const COVER_TRAFFIC_MEAN_SECS: f64 = 5.0;

// ── HybridRouter ─────────────────────────────────────────────────────────────

/// Manages hybrid communication (P2P + Relay)
#[derive(Clone)]
pub struct HybridRouter {
    ctx: SecureContext,
    #[cfg(feature = "p2p")]
    p2p_node: Option<Arc<P2pNode>>,
    #[cfg(feature = "p2p")]
    active_peers: Arc<DashMap<Vec<u8>, Arc<Peer>>>,
    cover_traffic_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Cancellation signal for the discovery background task. (FIX F-05)
    #[cfg(feature = "p2p")]
    discovery_cancel: Arc<tokio::sync::Notify>,
}

impl HybridRouter {
    pub fn new(ctx: SecureContext) -> Self {
        Self {
            ctx,
            #[cfg(feature = "p2p")]
            p2p_node: None,
            #[cfg(feature = "p2p")]
            active_peers: Arc::new(DashMap::new()),
            cover_traffic_enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(feature = "p2p")]
            discovery_cancel: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn set_cover_traffic(&self, enabled: bool) {
        self.cover_traffic_enabled.store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "p2p")]
    pub fn set_p2p_node(&mut self, node: P2pNode) {
        self.p2p_node = Some(Arc::new(node));
    }

    #[cfg(feature = "p2p")]
    pub fn p2p_node(&self) -> Option<Arc<P2pNode>> {
        self.p2p_node.clone()
    }

    /// Signal the discovery loop to stop. Call before dropping the router. (FIX F-05)
    #[cfg(feature = "p2p")]
    pub fn stop_discovery(&self) {
        self.discovery_cancel.notify_waiters();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    pub async fn send_message(&self, recipient_id: &[u8], plaintext: &[u8]) -> ProtocolResult<()> {
        // FIX F-06: reject oversized payloads before any allocation
        if plaintext.len() > MAX_MESSAGE_BYTES {
            warn!(
                "SEND_REJECTED: payload {} bytes exceeds {} limit",
                plaintext.len(), MAX_MESSAGE_BYTES
            );
            return Err(ProtocolError::InvalidArgument);
        }

        #[cfg(feature = "p2p")]
        {
            if let Some(ref node) = self.p2p_node {
                debug!("HybridRouter: P2P node available at {}", node.local_addr());
                if let Some(peer) = self.active_peers.get(recipient_id) {
                    debug!("Using existing P2P session for {}", hex::encode(recipient_id));
                    // FIX F-04: map to generic error, log details internally only
                    let res = peer.send_message(plaintext).await.map_err(|e| {
                        warn!("P2P_SEND_FAILED: recipient={} err={:?}", hex::encode(recipient_id), e);
                        ProtocolError::InternalError
                    });
                    if res.is_ok() {
                        return Ok(());
                    }
                    warn!("P2P_FALLBACK: recipient={}", hex::encode(recipient_id));
                }
            }
        }

        self.send_via_relay(recipient_id, plaintext).await
    }

    pub async fn send_webrtc_signal(&self, recipient_id: &[u8], signal: crate::media::WebRtcSignal) -> ProtocolResult<()> {
        let payload = crate::media::ProtocolPayload::WebRtc(signal);
        let bytes = payload.to_bytes()?;
        self.send_message(recipient_id, &bytes).await
    }

    pub async fn send_app_data(&self, recipient_id: &[u8], data: Vec<u8>) -> ProtocolResult<()> {
        let payload = crate::media::ProtocolPayload::Data(data);
        let bytes = payload.to_bytes()?;
        self.send_message(recipient_id, &bytes).await
    }

    // ── Discovery ─────────────────────────────────────────────────────────────

    #[cfg(feature = "p2p")]
    pub async fn start_discovery_loop(&self) -> ProtocolResult<()> {
        // FIX F-04: no internal detail in returned error
        let node = self.p2p_node.as_ref().ok_or(ProtocolError::InvalidState)?;

        let mut receiver = node.browse_peers().map_err(|e| {
            warn!("P2P_BROWSE_INIT_FAILED: {:?}", e);
            ProtocolError::InvalidState
        })?;

        let router     = Arc::new(self.clone());
        let node_local = node.clone();
        let cancel     = self.discovery_cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // FIX F-05: graceful shutdown
                    _ = cancel.notified() => {
                        info!("P2P discovery loop: shutdown requested, exiting");
                        break;
                    }

                    maybe = receiver.recv() => {
                        let discovered = match maybe {
                            Some(d) => d,
                            None    => { info!("P2P discovery channel closed"); break; }
                        };

                        // FIX F-02: validate hex before decode — no silent empty key
                        let peer_id = match hex::decode(&discovered.peer_id_hex) {
                            Ok(id) if !id.is_empty() => id,
                            Ok(_) => {
                                warn!("P2P_DISCOVERY: peer ID decodes to empty, dropping");
                                continue;
                            }
                            Err(e) => {
                                warn!("P2P_DISCOVERY: invalid peer ID hex '{}': {}", discovered.peer_id_hex, e);
                                continue;
                            }
                        };

                        // FIX F-07: validate address
                        if !is_valid_peer_addr(&discovered.addr) {
                            warn!("P2P_DISCOVERY: invalid addr {} for peer {}, dropping", discovered.addr, hex::encode(&peer_id));
                            continue;
                        }

                        // FIX F-03: enforce peer cap before attempting connect
                        if router.active_peers.len() >= MAX_ACTIVE_PEERS {
                            warn!("P2P_PEER_CAP: {} peers reached, dropping {}", MAX_ACTIVE_PEERS, hex::encode(&peer_id));
                            continue;
                        }

                        // FIX F-01: use DashMap entry API to close the TOCTOU window.
                        // The vacant slot is dropped before the async connect so we
                        // don't hold the shard lock across an await point.
                        // We then use or_insert_with on re-entry to handle the rare
                        // concurrent-connect race.
                        use dashmap::mapref::entry::Entry;
                        let already_present = matches!(
                            router.active_peers.entry(peer_id.clone()),
                            Entry::Occupied(_)
                        );
                        if already_present {
                            debug!("P2P_DISCOVERY: peer {} already connected", hex::encode(&peer_id));
                            continue;
                        }

                        match node_local.connect(&discovered.addr.to_string()).await {
                            Ok(peer) => {
                                // Idempotent: or_insert_with only inserts if still absent
                                router.active_peers
                                    .entry(peer_id.clone())
                                    .or_insert_with(|| {
                                        info!("P2P_CONNECTED: peer={} addr={}", hex::encode(&peer_id), discovered.addr);
                                        Arc::new(peer)
                                    });
                            }
                            Err(e) => {
                                // FIX F-04: log details but don't propagate them upward
                                warn!("P2P_CONNECT_FAILED: peer={} addr={} err={:?}", hex::encode(&peer_id), discovered.addr, e);
                            }
                        }
                    }
                }
            }
            info!("P2P discovery loop exited");
        });

        Ok(())
    }

    // ── Relay ─────────────────────────────────────────────────────────────────

    async fn send_via_relay(&self, recipient_id: &[u8], plaintext: &[u8]) -> ProtocolResult<()> {
        info!("RELAY_SEND: recipient={}", hex::encode(recipient_id));

        let ciphertext = self.ctx.encrypt_message(recipient_id, plaintext, None)
            .map_err(|e| {
                // FIX F-04: internal detail stays in logs, not in the error value
                warn!("RELAY_ENCRYPT_FAILED: {:?}", e);
                ProtocolError::EncryptionFailed
            })?;

        info!("RELAY_QUEUED: {} bytes", ciphertext.len());
        Ok(())
    }

    // ── Peer management ───────────────────────────────────────────────────────

    /// Register a new P2P peer. Returns false if the peer cap is reached. (FIX F-03)
    #[cfg(feature = "p2p")]
    pub fn add_p2p_peer(&self, peer: Peer) -> bool {
        if self.active_peers.len() >= MAX_ACTIVE_PEERS {
            warn!("P2P_PEER_CAP: cap {} reached, refusing peer {}", MAX_ACTIVE_PEERS, hex::encode(peer.peer_id()));
            return false;
        }
        let id = peer.peer_id().to_vec();
        info!("P2P_REGISTERED: peer={}", hex::encode(&id));
        self.active_peers.insert(id, Arc::new(peer));
        true
    }

    // ── Cover traffic ─────────────────────────────────────────────────────────

    pub fn start_cover_traffic_loop(&self, min_delay_sec: u64, max_delay_sec: u64) {
        #[cfg(not(feature = "p2p"))]
        { let _ = (min_delay_sec, max_delay_sec); }

        #[cfg(feature = "p2p")]
        {
            let router = self.clone();
            tokio::spawn(async move {
                loop {
                    if !router.cover_traffic_enabled.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }

                    // FIX F-08: exponential distribution instead of uniform.
                    // Exponential inter-arrival times produce a Poisson process,
                    // which is much harder to distinguish from background traffic.
                    let delay_secs = {
                        let u: f64 = rand::thread_rng().gen_range(0.0001..=1.0);
                        let exp_delay = -f64::ln(u) * COVER_TRAFFIC_MEAN_SECS;
                        exp_delay.clamp(min_delay_sec as f64, max_delay_sec as f64) as u64
                    };
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

                    let dummy_id = [0u8; 32];
                    if let Err(e) = router.send_dummy_to_relay(&dummy_id) {
                        warn!("COVER_TRAFFIC_SEND_FAILED: {:?}", e);
                    }
                }
            });
        }
    }

    #[allow(dead_code)]
    fn send_dummy_to_relay(&self, recipient_id: &[u8]) -> ProtocolResult<()> {
        debug!("COVER_TRAFFIC_DUMMY: recipient={}", hex::encode(recipient_id));

        let mut junk = vec![0u8; 64];
        rand::thread_rng().fill(&mut junk[..]);

        let ciphertext = self.ctx.encrypt_message(recipient_id, &junk, None)?;

        let identity = self.ctx.get_identity().map_err(|e| {
            // FIX F-04: generic error returned, detail logged internally
            warn!("COVER_TRAFFIC_IDENTITY_ERR: {:?}", e);
            ProtocolError::InternalError
        })?;

        // VERIFIED: is_dummy IS included in signing_payload() — see metadata.rs
        // line 121: `hasher.update(&[self.is_dummy as u8])`.
        // Original audit finding #3 was a false positive.
        let mut sig_env = crate::metadata::SignedEnvelope {
            recipient_id:  hex::encode(recipient_id),
            payload_hex:   hex::encode(ciphertext),
            sender_id:     hex::encode(&identity.ed25519_public),
            timestamp:     chrono::Utc::now().timestamp(),
            message_id:    hex::encode(rand::thread_rng().gen::<[u8; 16]>()),
            signature_hex: String::new(),
            compressed:    false,
            is_dummy:      true, // ← hashed into signing_payload
        };

        let payload = sig_env.signing_payload();
        sig_env.signature_hex = hex::encode(identity.sign(&payload)?);

        let final_json = serde_json::to_string(&sig_env)
            .map_err(|_| ProtocolError::InvalidMessage)?;

        info!("COVER_TRAFFIC_SENT: {} bytes", final_json.len());
        Ok(())
    }
}

// ── Address validation ────────────────────────────────────────────────────────

/// Returns true only for addresses safe to dial. (FIX F-07)
#[cfg(feature = "p2p")]
fn is_valid_peer_addr(addr: &std::net::SocketAddr) -> bool {
    let ip = addr.ip();
    // Reject unroutable / control addresses
    if ip.is_loopback()    { return false; } // 127.x / ::1
    if ip.is_multicast()   { return false; } // 224.x / ff00::/8
    if ip.is_unspecified() { return false; } // 0.0.0.0 / ::
    if addr.port() == 0    { return false; } // unassigned port
    true
    // NOTE: RFC-1918 private addresses are intentionally allowed — mDNS
    // discovery is LAN-scoped by design. Revisit if the discovery layer
    // ever extends to public networks.
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[cfg(feature = "p2p")]
    use super::is_valid_peer_addr;

    #[cfg(feature = "p2p")]
    #[test]
    fn rejects_loopback() {
        assert!(!is_valid_peer_addr(&"127.0.0.1:4000".parse().unwrap()));
        assert!(!is_valid_peer_addr(&"[::1]:4000".parse().unwrap()));
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn rejects_unspecified() {
        assert!(!is_valid_peer_addr(&"0.0.0.0:4000".parse().unwrap()));
        assert!(!is_valid_peer_addr(&"[::]:4000".parse().unwrap()));
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn rejects_zero_port() {
        assert!(!is_valid_peer_addr(&"192.168.1.5:0".parse().unwrap()));
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn allows_lan_address() {
        assert!(is_valid_peer_addr(&"192.168.1.100:4000".parse().unwrap()));
        assert!(is_valid_peer_addr(&"10.0.0.5:9000".parse().unwrap()));
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn allows_public_address() {
        assert!(is_valid_peer_addr(&"203.0.113.5:4000".parse().unwrap()));
    }
}
