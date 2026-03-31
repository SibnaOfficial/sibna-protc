//! WebSocket Transport Layer — Real-Time Message Relay
//!
//! The server is a pure relay: it NEVER sees plaintext. It routes sealed
//! envelopes between connected clients. Disconnected recipients get messages
//! queued in sled with a 7-day TTL.

use axum::{
    extract::{State, WebSocketUpgrade, Query},
    response::IntoResponse,
};
use axum::extract::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use futures_util::{SinkExt, StreamExt};
use tracing::{info, warn};
use crate::{AppState, auth::validate_jwt};

/// A sender channel for pushing messages to a connected client
pub type ClientTx = mpsc::UnboundedSender<Vec<u8>>;

/// Globally connected clients: identity_key_hex -> channel
pub type ConnectedClients = Arc<DashMap<String, ClientTx>>;

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
}

/// Upgrade HTTP connection to WebSocket
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Validate JWT before upgrade
    let claims = match validate_jwt(&params.token, &state.jwt_secret) {
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
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Register this client
    state.clients.insert(identity_id.clone(), tx.clone());
    info!("Client connected: {}", &identity_id[..16]);

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
        while let Some(Ok(msg)) = receiver.next().await {
            let raw: Option<Vec<u8>> = match msg {
                Message::Binary(data) => Some(data),
                Message::Text(text) => Some(text.into_bytes()),
                Message::Close(_) => break,
                _ => None,
            };
            if let Some(bytes) = raw {
                if let Ok(envelope) = serde_json::from_slice::<SealedEnvelope>(&bytes) {
                    route_message(&state_clone, &id_clone, envelope).await;
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
    state.clients.remove(&identity_id);
    info!("Client disconnected: {}", &identity_id[..16]);
}

/// Route a sealed envelope to recipient or queue it
async fn route_message(state: &AppState, sender_id: &str, mut envelope: SealedEnvelope) {
    // Validate message_id (dedup)
    let dedup_tree = state.db.open_tree("msg_dedup").expect("db");
    let dedup_key = format!("dedup:{}", envelope.message_id);
    if dedup_tree.get(dedup_key.as_bytes()).ok().flatten().is_some() {
        warn!("Duplicate message_id dropped: {}", envelope.message_id);
        return;
    }
    dedup_tree.insert(dedup_key.as_bytes(), b"1").ok();

    // Stamp the timestamp
    envelope.timestamp = chrono::Utc::now().timestamp();

    // Try to deliver immediately if recipient is online
    if let Some(recipient_tx) = state.clients.get(&envelope.recipient_id) {
        let data = serde_json::to_vec(&envelope).unwrap_or_default();
        if recipient_tx.send(data).is_ok() {
            return;
        }
    }

    // Recipient is offline — queue message with 7-day TTL
    queue_message(state, &envelope).await;
}

/// Store message in offline queue (sled tree: "msg_queue:{recipient_id}:{msg_id}")
async fn queue_message(state: &AppState, envelope: &SealedEnvelope) {
    let tree = state.db.open_tree("msg_queue").expect("db");
    let db_key = format!("queue:{}:{}", envelope.recipient_id, envelope.message_id);
    let ttl_cutoff = chrono::Utc::now().timestamp() + 7 * 86400;
    let value = serde_json::json!({
        "envelope": envelope,
        "expires": ttl_cutoff,
    });
    if let Ok(bytes) = serde_json::to_vec(&value) {
        tree.insert(db_key.as_bytes(), bytes).ok();
    }
    info!("Queued message for offline recipient: {}", &envelope.recipient_id[..16]);
}

/// Deliver all queued messages to a newly connected client
async fn deliver_queued_messages(state: &AppState, identity_id: &str, tx: &ClientTx) {
    let tree = match state.db.open_tree("msg_queue") {
        Ok(t) => t,
        Err(_) => return,
    };

    let prefix = format!("queue:{}:", identity_id);
    let now = chrono::Utc::now().timestamp();
    let mut to_delete = Vec::new();

    for item in tree.scan_prefix(prefix.as_bytes()) {
        if let Ok((key, value)) = item {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&value) {
                let expires = json["expires"].as_i64().unwrap_or(0);
                if now > expires {
                    // Expired — mark for deletion
                    to_delete.push(key);
                    continue;
                }
                if let Ok(envelope) = serde_json::from_value::<SealedEnvelope>(json["envelope"].clone()) {
                    let data = serde_json::to_vec(&envelope).unwrap_or_default();
                    tx.send(data).ok();
                    to_delete.push(key);
                }
            }
        }
    }

    // Remove delivered/expired messages
    for key in to_delete {
        tree.remove(key).ok();
    }
}
