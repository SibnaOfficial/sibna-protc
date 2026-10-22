//! WebSocket Transport Layer — Real-Time Message Relay
//!
//! The server is a pure relay: it NEVER sees plaintext. It routes sealed
//! envelopes between connected clients. Disconnected recipients get messages
//! queued in redb with a 7-day TTL.

use crate::{auth::validate_jwt, AppState};
use axum::extract::ws::{Message, WebSocket};
use axum::{
    extract::{Query, State, WebSocketUpgrade},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// A sender channel for pushing messages to a connected client
pub type ClientTx = mpsc::UnboundedSender<Vec<u8>>;

/// Query parameters for WebSocket upgrade
#[derive(Deserialize)]
pub struct WsQuery {
    /// JWT token for authentication
    pub token: String,
}

/// Sealed envelope routed over WebSocket
#[derive(Serialize, Deserialize, Clone)]
pub struct SealedEnvelope {
    /// Recipient identity key hex (32 bytes = 64 hex chars)
    pub recipient_id: String,
    /// Encrypted payload — server cannot read this
    pub payload_hex: String,
    /// Optional LZ4-compressed flag (for IoT low-bandwidth mode)
    pub compressed: bool,
    /// Unique message ID for deduplication
    pub message_id: String,
    /// Timestamp (unix seconds)
    pub timestamp: i64,
    /// Sender identity key hex (32 bytes = 64 hex chars). Part of the signed
    /// canonical payload so the sender is authenticated.
    pub sender_id: String,
    /// Ed25519 signature of (recipient_id + message_id + payload_hex + sender_id)
    /// signed by sender's identity key.
    /// Hex-encoded, 64 bytes. Required for message authenticity.
    pub signature_hex: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WebRtcSignal {
    pub recipient_id: String,
    pub payload_hex: String, // Encrypted SDP or ICE candidate
    pub signature_hex: String,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum WsMessage {
    #[serde(rename = "envelope")]
    Envelope(SealedEnvelope),

    #[serde(rename = "ack")]
    Ack { message_id: String },

    #[serde(rename = "webrtc")]
    WebRtc(WebRtcSignal),
}

/// Upgrade HTTP connection to WebSocket
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Validate JWT before upgrade
    let claims = match validate_jwt(&params.token, &state.rt.jwt_secret) {
        Some(c) => c,
        None => {
            return (axum::http::StatusCode::UNAUTHORIZED, "Invalid token").into_response();
        }
    };

    let identity_id = claims.sub.clone();
    ws.on_upgrade(move |socket| handle_ws(socket, identity_id, state))
}

/// Handle an authenticated WebSocket connection
async fn handle_ws(socket: WebSocket, identity_id: String, state: AppState) {
    // : WebSocket read timeout is now configurable via
    // SIBNA_WS_TIMEOUT_SECS (default: 120). The previous hardcoded 10s was too
    // aggressive for slow connections (2G, satellite) and could not be tuned.
    let ws_timeout_secs: u64 = std::env::var("SIBNA_WS_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    let ws_timeout = std::time::Duration::from_secs(ws_timeout_secs);

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Register this client
    state.rt.clients.insert(identity_id.clone(), tx.clone());
    info!(
        "Client connected: {}",
        identity_id.get(..16).unwrap_or(&identity_id)
    );

    // Deliver any queued offline messages
    deliver_queued_messages(&state, &identity_id, &tx).await;

    // Task: forward outbound channel messages to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(Message::Binary(msg)).await.is_err() {
                break;
            }
        }
    });

    // Task: receive from WebSocket and route to recipient
    let state_clone = state.clone();
    let id_clone = identity_id.clone();
    let recv_task = tokio::spawn(async move {
        loop {
            // : Apply configurable idle timeout per message receive.
            // Stale/zombie connections are terminated after ws_timeout_secs of inactivity.
            let msg_result = tokio::time::timeout(ws_timeout, receiver.next()).await;
            let frame = match msg_result {
                Err(_elapsed) => {
                    warn!(
                        "WS_TIMEOUT: client {} idle for {}s — disconnecting",
                        id_clone.get(..16).unwrap_or(&id_clone),
                        ws_timeout_secs
                    );
                    break;
                }
                Ok(None) => break,
                Ok(Some(Err(_))) => break,
                Ok(Some(Ok(msg))) => msg,
            };
            let raw: Option<Vec<u8>> = match frame {
                Message::Binary(data) => Some(data),
                Message::Text(text) => Some(text.into_bytes()),
                Message::Close(_) => break,
                _ => None,
            };
            if let Some(bytes) = raw {
                // Backward-compatible JSON parsing: Try WsMessage format first, fallback to raw SealedEnvelope
                let msg_parsed = serde_json::from_slice::<WsMessage>(&bytes).or_else(|_| {
                    serde_json::from_slice::<SealedEnvelope>(&bytes).map(WsMessage::Envelope)
                });

                if let Ok(ws_msg) = msg_parsed {
                    match ws_msg {
                        WsMessage::Envelope(envelope) => {
                            route_message(&state_clone, &id_clone, envelope).await
                        }
                        WsMessage::Ack { message_id } => {
                            handle_ack(&state_clone, &id_clone, &message_id).await
                        }
                        WsMessage::WebRtc(signal) => {
                            route_webrtc(&state_clone, &id_clone, signal).await
                        }
                    }
                } else {
                    warn!(
                        "WS_PARSE: Received invalid message from {}",
                        id_clone.get(..16).unwrap_or(&id_clone)
                    );
                }
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    // Unregister client
    state.rt.clients.remove(&identity_id);
    info!(
        "Client disconnected: {}",
        identity_id.get(..16).unwrap_or(&identity_id)
    );
}

/// Route a sealed envelope to recipient or queue it
async fn route_message(state: &AppState, sender_id: &str, mut envelope: SealedEnvelope) {
    // Validate message_id length to prevent key-bloat DoS on the dedup tree.
    if envelope.message_id.is_empty() || envelope.message_id.len() > 128 {
        warn!(
            "Dropping message with invalid message_id from {}",
            sender_id.get(..16).unwrap_or(sender_id)
        );
        return;
    }

    // Validate recipient_id format (must be 64 hex chars = 32-byte key)
    if envelope.recipient_id.len() != 64
        || !envelope.recipient_id.chars().all(|c| c.is_ascii_hexdigit())
    {
        warn!(
            "Dropping message with invalid recipient_id from {}",
            sender_id.get(..16).unwrap_or(sender_id)
        );
        return;
    }

    // Validate payload_hex size. RequestBodyLimitLayer (64 KB) applies to
    // HTTP requests only — WebSocket frames bypass it. Limit to 20 MB hex (= 10 MB payload).
    const MAX_PAYLOAD_HEX_LEN: usize = 20 * 1024 * 1024;
    if envelope.payload_hex.len() > MAX_PAYLOAD_HEX_LEN {
        warn!(
            "Dropping oversized payload ({} bytes hex) from {}",
            envelope.payload_hex.len(),
            sender_id.get(..16).unwrap_or(sender_id)
        );
        return;
    }

    // Validate message_id (dedup) — with INLINE TTL eviction for expired entries.
    let dedup_key = format!("dedup:{}", envelope.message_id);
    if let Ok(Some(existing)) = state.db.tree_dedup.get(dedup_key.as_bytes()) {
        let existing: Vec<u8> = existing;
        let is_expired = if existing.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&existing);
            let ts = i64::from_be_bytes(b);
            ts < chrono::Utc::now().timestamp() - 48 * 3600
        } else {
            // Legacy string entries: treat as expired (prune them)
            true
        };

        if !is_expired {
            warn!(
                "Duplicate message_id dropped from {}: {}",
                sender_id.get(..16).unwrap_or(sender_id),
                envelope.message_id
            );
            return;
        }
        // Expired entry — evict inline before re-inserting
        state.db.tree_dedup.remove(dedup_key.as_bytes()).ok();
    }
    // Store insertion timestamp (binary i64) for future dedup checks.
    let ts_bytes = chrono::Utc::now().timestamp().to_be_bytes();
    state
        .db
        .tree_dedup
        .insert(dedup_key.as_bytes(), &ts_bytes)
        .ok();

    // CRYPTO: Verify Ed25519 signature from the sender.
    // The sender MUST sign a canonical payload that unambiguously encodes all fields.
    //
    // attack: if recipient_id="AABB", message_id="CCDD" produces the same string as
    // recipient_id="AABBCC", message_id="DD", an attacker can redirect a legitimate
    // message to a different recipient using the original sender's valid signature.
    //
    // NEW FORMAT: Each field is length-prefixed (8-byte big-endian u64) before its value:
    //   len(recipient_id_bytes) || recipient_id_bytes
    //   len(message_id_bytes)   || message_id_bytes
    //   len(payload_hex_bytes)  || payload_hex_bytes
    //
    // field boundaries unambiguous and prevents any overlap attack.
    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use std::io::Write;

        let mut canonical: Vec<u8> = Vec::with_capacity(
            4 * 8
                + envelope.recipient_id.len()
                + envelope.message_id.len()
                + envelope.payload_hex.len()
                + envelope.sender_id.len(),
        );
        let r = envelope.recipient_id.as_bytes();
        let m = envelope.message_id.as_bytes();
        let p = envelope.payload_hex.as_bytes();
        let s = envelope.sender_id.as_bytes();
        canonical.write_all(&(r.len() as u64).to_be_bytes()).ok();
        canonical.write_all(r).ok();
        canonical.write_all(&(m.len() as u64).to_be_bytes()).ok();
        canonical.write_all(m).ok();
        canonical.write_all(&(p.len() as u64).to_be_bytes()).ok();
        canonical.write_all(p).ok();
        canonical.write_all(&(s.len() as u64).to_be_bytes()).ok();
        canonical.write_all(s).ok();

        let key_bytes = match hex::decode(sender_id) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                warn!(
                    "WS_AUTH: invalid sender_id hex from {}",
                    sender_id.get(..16).unwrap_or(sender_id)
                );
                return;
            }
        };
        let key_arr: [u8; 32] = match key_bytes.try_into() {
            Ok(a) => a,
            Err(_) => {
                return;
            }
        };
        let verifying_key = match VerifyingKey::from_bytes(&key_arr) {
            Ok(k) => k,
            Err(_) => {
                warn!(
                    "WS_AUTH: invalid Ed25519 key from {}",
                    sender_id.get(..16).unwrap_or(sender_id)
                );
                return;
            }
        };
        let sig_bytes = match hex::decode(&envelope.signature_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => {
                warn!(
                    "WS_AUTH: missing or invalid signature from {}",
                    sender_id.get(..16).unwrap_or(sender_id)
                );
                return;
            }
        };
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => {
                return;
            }
        };
        let signature = Signature::from_bytes(&sig_arr);
        if verifying_key.verify(&canonical, &signature).is_err() {
            warn!(
                "WS_AUTH: signature verification failed from {}",
                sender_id.get(..16).unwrap_or(sender_id)
            );
            return;
        }
    }

    // Stamp the timestamp (server-side; ignore client-supplied value)
    envelope.timestamp = chrono::Utc::now().timestamp();

    // PILLAR 1: Delivery ACKs & Retries
    // We ALWAYS queue the message first so it isn't lost if the live connection drops milliseconds later.
    queue_message(state, &envelope).await;

    // Try to deliver immediately if recipient is online
    if let Some(recipient_tx) = state.rt.clients.get(&envelope.recipient_id) {
        match serde_json::to_vec(&WsMessage::Envelope(envelope.clone())) {
            Ok(data) => {
                recipient_tx.send(data).ok();
            }
            Err(e) => {
                warn!(
                    "WS_ROUTE: failed to serialize envelope for {}: {}",
                    envelope
                        .recipient_id
                        .get(..16)
                        .unwrap_or(&envelope.recipient_id),
                    e
                );
            }
        }
    }
}

/// Store message in offline queue (redb table: "queue:{recipient_id}:{msg_id}")
async fn queue_message(state: &AppState, envelope: &SealedEnvelope) {
    let db_key = format!("queue:{}:{}", envelope.recipient_id, envelope.message_id);
    let ttl_cutoff = chrono::Utc::now().timestamp() + 7 * 86400;
    let value = serde_json::json!({
        "envelope": envelope,
        "expires": ttl_cutoff,
    });
    if let Ok(bytes) = serde_json::to_vec(&value) {
        state.db.tree_queue.insert(db_key.as_bytes(), bytes).ok();
    }
    info!(
        "Queued message for offline recipient: {}",
        envelope
            .recipient_id
            .get(..16)
            .unwrap_or(&envelope.recipient_id)
    );
}

/// Deliver all queued messages to a newly connected client
async fn deliver_queued_messages(state: &AppState, identity_id: &str, tx: &ClientTx) {
    let prefix = format!("queue:{}:", identity_id);
    let now = chrono::Utc::now().timestamp();
    let mut to_delete = Vec::new();

    for (key, value) in state.db.tree_queue.scan_prefix(prefix.as_bytes()) {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&value) {
            let expires = json["expires"].as_i64().unwrap_or(0);
            if now > expires {
                // Expired — mark for deletion
                to_delete.push(key);
                continue;
            }
            if let Some(env_val) = json.get("envelope") {
                if let Ok(envelope) = serde_json::from_value::<SealedEnvelope>(env_val.clone()) {
                    match serde_json::to_vec(&WsMessage::Envelope(envelope)) {
                        Ok(data) => {
                            tx.send(data).ok();
                        }
                        Err(e) => {
                            warn!("WS_DELIVER: failed to serialise queued envelope: {}", e);
                        }
                    }
                    // PILLAR 1: DO NOT mark for deletion! Waiting for explicit client ACK.
                }
            } else if let Some(sig_val) = json.get("signal") {
                if let Ok(signal) = serde_json::from_value::<WebRtcSignal>(sig_val.clone()) {
                    match serde_json::to_vec(&WsMessage::WebRtc(signal)) {
                        Ok(data) => {
                            tx.send(data).ok();
                        }
                        Err(e) => {
                            warn!("WS_DELIVER: failed to serialise queued signal: {}", e);
                        }
                    }
                    // WebRTC signals are ephemeral — safe to delete upon delivery attempt to prevent ghost ringing.
                    to_delete.push(key);
                }
            }
        }
    }

    // Remove ONLY expired messages and ephemeral WebRTC signals
    for key in to_delete {
        state.db.tree_queue.remove(key).ok();
    }
}

/// Handle a client ACK for a message — permanently removes it from the queue
async fn handle_ack(state: &AppState, identity_id: &str, message_id: &str) {
    let db_key = format!("queue:{}:{}", identity_id, message_id);
    if state
        .db
        .tree_queue
        .remove(db_key.as_bytes())
        .unwrap_or_default()
        .is_some()
    {
        info!(
            "ACK received from {}. Message permanently removed from queue.",
            identity_id.get(..16).unwrap_or(identity_id)
        );
    }
}

/// Route an ephemeral WebRTC Signal (Offer/Answer/ICE)
async fn route_webrtc(state: &AppState, sender_id: &str, mut signal: WebRtcSignal) {
    if signal.recipient_id.len() != 64 {
        return;
    }

    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use std::io::Write;
        // Same canonical length-prefixed format as route_message.
        let mut canonical: Vec<u8> =
            Vec::with_capacity(2 * 8 + signal.recipient_id.len() + signal.payload_hex.len());
        let r = signal.recipient_id.as_bytes();
        let p = signal.payload_hex.as_bytes();
        canonical.write_all(&(r.len() as u64).to_be_bytes()).ok();
        canonical.write_all(r).ok();
        canonical.write_all(&(p.len() as u64).to_be_bytes()).ok();
        canonical.write_all(p).ok();

        let key_bytes = match hex::decode(sender_id) {
            Ok(b) if b.len() == 32 => b,
            _ => return,
        };
        let key_arr: [u8; 32] = match key_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return,
        };
        let verifying_key = match VerifyingKey::from_bytes(&key_arr) {
            Ok(k) => k,
            Err(_) => return,
        };
        let sig_bytes = match hex::decode(&signal.signature_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return,
        };
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return,
        };
        let signature = Signature::from_bytes(&sig_arr);
        if verifying_key.verify(&canonical, &signature).is_err() {
            warn!(
                "WS_WEBRTC: signature verification failed from {}",
                sender_id.get(..16).unwrap_or(sender_id)
            );
            return;
        }
    }

    signal.timestamp = chrono::Utc::now().timestamp();

    if let Some(recipient_tx) = state.rt.clients.get(&signal.recipient_id) {
        if let Ok(data) = serde_json::to_vec(&WsMessage::WebRtc(signal.clone())) {
            if recipient_tx.send(data).is_ok() {
                return;
            }
        }
    }

    // Queue signal with a very short TTL (60 seconds) because WebRTC session states fast-expire
    let db_key = format!(
        "queue:{}:webrtc_{}",
        signal.recipient_id,
        uuid::Uuid::new_v4()
    );
    let ttl_cutoff = chrono::Utc::now().timestamp() + 60;
    let value = serde_json::json!({
        "signal": signal,
        "expires": ttl_cutoff,
    });
    if let Ok(bytes) = serde_json::to_vec(&value) {
        state.db.tree_queue.insert(db_key.as_bytes(), bytes).ok();
    }
}
