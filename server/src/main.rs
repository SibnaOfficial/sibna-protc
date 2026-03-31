//! Sibna Universal Server v11.0
//! Zero-Trust, Multi-Transport Messaging Infrastructure
//!
//! Transports:
//!   - REST (HTTP) — prekey operations + auth
//!   - WebSocket — real-time sealed-envelope relay
//!
//! Security Layers:
//!   - Ed25519 identity binding
//!   - JWT challenge-response auth
//!   - Hybrid rate limiting (IP + Identity)
//!   - Bundle replay protection (bundle_id dedup)
//!   - Sealed Sender (server never sees sender)
//!   - Offline message queue (7-day TTL, sled)
//!   - Zero-Reuse prekey compaction

mod auth;
mod ws;

use axum::{
    extract::{Path, State, ConnectInfo},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sibna_core::rate_limit::RateLimiter;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};

// ─── Shared Application State ────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub db: sled::Db,
    pub limiter: Arc<RateLimiter>,
    /// Connected WebSocket clients: identity_key_hex → sender channel
    pub clients: Arc<DashMap<String, ws::ClientTx>>,
    /// JWT signing secret (from env or random on startup)
    pub jwt_secret: Arc<String>,
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Database
    let db_path = std::env::var("SIBNA_DB_PATH")
        .unwrap_or_else(|_| "sibna_server_db".to_string());
    let db = sled::open(&db_path).expect("Failed to open sled database");
    info!("Database opened at '{}'", db_path);

    // JWT secret (set SIBNA_JWT_SECRET in env for production)
    let jwt_secret = Arc::new(
        std::env::var("SIBNA_JWT_SECRET")
            .unwrap_or_else(|_| {
                warn!("⚠  SIBNA_JWT_SECRET not set — generating ephemeral secret (restarts invalidate tokens!)");
                hex::encode(random_bytes_32())
            })
    );

    // Rate limiter — separate limits per operation
    let mut limiter = RateLimiter::new();
    limiter.set_global_enabled(true);
    limiter.set_global_rps(5000);

    let prekey_limit = sibna_core::rate_limit::OperationLimit {
        max_per_second: 50,
        max_per_minute: 500,
        max_per_hour: 10_000,
        max_per_day: 100_000,
        cooldown: Duration::from_secs(1),
        burst_size: 20,
    };
    let tight_limit = sibna_core::rate_limit::OperationLimit {
        max_per_second: 5,
        max_per_minute: 30,
        max_per_hour: 300,
        max_per_day: 3_000,
        cooldown: Duration::from_secs(10),
        burst_size: 3,
    };

    limiter.add_limit("prekey_upload".to_string(), prekey_limit.clone());
    limiter.add_limit("prekey_fetch".to_string(), prekey_limit);
    limiter.add_limit("auth_challenge".to_string(), tight_limit.clone());
    limiter.add_limit("auth_prove".to_string(), tight_limit);
    limiter.add_limit("inbox_fetch".to_string(), sibna_core::rate_limit::OperationLimit {
        max_per_second: 10,
        max_per_minute: 100,
        max_per_hour: 1_000,
        max_per_day: 10_000,
        cooldown: Duration::from_secs(2),
        burst_size: 5,
    });

    let state = AppState {
        db,
        limiter: Arc::new(limiter),
        clients: Arc::new(DashMap::new()),
        jwt_secret,
    };

    // Router
    let app = Router::new()
        // ── Health ───────────────────────────────────────────────────────────
        .route("/health", get(health_handler))

        // ── Auth ─────────────────────────────────────────────────────────────
        .route("/v1/auth/challenge", post(auth::challenge_handler))
        .route("/v1/auth/prove", post(auth::prove_handler))

        // ── PreKey ───────────────────────────────────────────────────────────
        .route("/v1/prekeys/upload", post(upload_prekey_handler))
        .route("/v1/prekeys/:user_id", get(fetch_prekey_handler))
        .route("/v1/prekeys/:user_id", delete(delete_prekey_handler))

        // ── Sealed Messages (REST fallback for HTTP-only devices) ─────────────
        .route("/v1/messages/send", post(send_message_handler))
        .route("/v1/messages/inbox", get(inbox_handler))

        // ── WebSocket real-time relay ─────────────────────────────────────────
        .route("/ws", get(ws::ws_handler))

        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(64 * 1024)) // 64 KB max body
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any),
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("🚀 Sibna Universal Server v11.0 listening on {}", addr);
    info!("   Transports: REST + WebSocket");
    info!("   Auth: Ed25519 Challenge-Response / JWT");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn generate_rate_key(ip: &SocketAddr, identity: &str) -> String {
    let mut hasher = DefaultHasher::new();
    ip.ip().hash(&mut hasher);
    identity.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn enforce_rate_limit(
    limiter: &RateLimiter,
    operation: &str,
    ip: &SocketAddr,
    identity: &str,
) -> Result<(), axum::response::Response> {
    let key = generate_rate_key(ip, identity);
    if let Err(e) = limiter.check(operation, &key) {
        warn!("Rate limit exceeded for {} ({}): {}", operation, &identity[..identity.len().min(16)], e);
        return Err((StatusCode::TOO_MANY_REQUESTS, e.to_string()).into_response());
    }
    Ok(())
}

fn random_bytes_32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "status": "ok",
        "version": "11.0.0",
        "transports": ["http", "websocket"],
        "auth": "ed25519-jwt"
    })))
}

// ── PreKey Upload ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct UploadPrekeyRequest {
    bundle_hex: String,
}

async fn upload_prekey_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(payload): Json<UploadPrekeyRequest>,
) -> impl IntoResponse {
    if let Err(r) = enforce_rate_limit(&state.limiter, "prekey_upload", &addr, "upload_ip") {
        return r;
    }

    let bundle_bytes = match hex::decode(&payload.bundle_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid hex encoding").into_response(),
    };

    let bundle = match sibna_core::handshake::PreKeyBundle::from_bytes(&bundle_bytes) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Malformed PreKeyBundle").into_response(),
    };

    if let Err(e) = bundle.validate() {
        return (StatusCode::BAD_REQUEST, format!("Invalid bundle: {:?}", e)).into_response();
    }

    let root_id = hex::encode(&bundle.root_identity_key);
    let db_key = format!("{}:{}", root_id, bundle.device_id);

    if let Err(r) = enforce_rate_limit(&state.limiter, "prekey_upload", &addr, &root_id) {
        return r;
    }

    let tree = state.db.open_tree("prekeys").unwrap();
    if let Ok(Some(existing)) = tree.get(&db_key) {
        if let Ok(existing_bundle) = sibna_core::handshake::PreKeyBundle::from_bytes(&existing) {
            if bundle.bundle_id == existing_bundle.bundle_id {
                return (StatusCode::CONFLICT, "Replay attack detected: bundle_id reused").into_response();
            }
        }
    }

    tree.insert(db_key.as_bytes(), bundle_bytes).unwrap();
    info!("PreKey uploaded for Root {} Device {}", &root_id[..16], bundle.device_id);
    StatusCode::OK.into_response()
}

// ── PreKey Fetch ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct FetchPrekeyResponse {
    bundles_hex: Vec<String>,
}

async fn fetch_prekey_handler(
    Path(root_id): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Err(r) = enforce_rate_limit(&state.limiter, "prekey_fetch", &addr, &root_id) {
        return r;
    }

    let tree = state.db.open_tree("prekeys").unwrap();
    let prefix = format!("{}:", root_id);
    let mut fetched_bundles_hex = Vec::new();
    let mut keys_to_delete = Vec::new();

    for item in tree.scan_prefix(prefix.as_bytes()) {
        if let Ok((key, bundle_bytes)) = item {
            if let Ok(bundle) = sibna_core::handshake::PreKeyBundle::from_bytes(&bundle_bytes) {
                if bundle.validate().is_ok() {
                    fetched_bundles_hex.push(hex::encode(&*bundle_bytes));
                }
            }
            keys_to_delete.push(key);
        }
    }

    if fetched_bundles_hex.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Zero-Reuse: delete after fetch
    for key in keys_to_delete {
        let _ = tree.remove(key);
    }
    info!("Fetched {} PreKey(s) and compacted for {}", fetched_bundles_hex.len(), &root_id[..16]);

    (StatusCode::OK, Json(FetchPrekeyResponse {
        bundles_hex: fetched_bundles_hex,
    })).into_response()
}

async fn delete_prekey_handler(
    Path(root_id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let tree = state.db.open_tree("prekeys").unwrap();
    let prefix = format!("{}:", root_id);
    let mut deleted = false;
    for item in tree.scan_prefix(prefix.as_bytes()) {
        if let Ok((key, _)) = item {
            if tree.remove(key).unwrap_or(None).is_some() {
                deleted = true;
            }
        }
    }
    if deleted {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

// ── Sealed Message REST Endpoint (HTTP fallback for IoT/no-WS) ─────────────

#[derive(Deserialize)]
struct SendMessageRequest {
    /// Recipient identity_key hex
    recipient_id: String,
    /// Encrypted payload (hex) — server cannot read
    payload_hex: String,
    /// LZ4 compressed?
    compressed: Option<bool>,
}

async fn send_message_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<SendMessageRequest>,
) -> impl IntoResponse {
    // Rate limit
    if let Err(r) = enforce_rate_limit(&state.limiter, "prekey_upload", &addr, &req.recipient_id) {
        return r;
    }

    let envelope = ws::SealedEnvelope {
        recipient_id: req.recipient_id.clone(),
        payload_hex: req.payload_hex,
        compressed: req.compressed.unwrap_or(false),
        message_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp(),
    };

    // Try to push to connected WebSocket client
    if let Some(client_tx) = state.clients.get(&req.recipient_id) {
        if let Ok(data) = serde_json::to_vec(&envelope) {
            if client_tx.send(data).is_ok() {
                info!("Message delivered live to {}", &req.recipient_id[..16]);
                return StatusCode::OK.into_response();
            }
        }
    }

    // Recipient offline — queue it
    let tree = state.db.open_tree("msg_queue").expect("db");
    let db_key = format!("queue:{}:{}", envelope.recipient_id, envelope.message_id);
    let ttl = chrono::Utc::now().timestamp() + 7 * 86400;
    let value = serde_json::json!({ "envelope": envelope, "expires": ttl });
    if let Ok(bytes) = serde_json::to_vec(&value) {
        tree.insert(db_key.as_bytes(), bytes).ok();
        info!("Message queued for offline recipient {}", &req.recipient_id[..16]);
    }

    StatusCode::ACCEPTED.into_response()
}

// ── Inbox Fetch (for HTTP-only devices that cannot use WS) ─────────────────

#[derive(Deserialize)]
struct InboxQuery {
    identity_key_hex: String,
    token: String,
}

async fn inbox_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<InboxQuery>,
) -> impl IntoResponse {
    // Validate JWT
    let claims = match auth::validate_jwt(&q.token, &state.jwt_secret) {
        Some(c) if c.sub == q.identity_key_hex => c,
        _ => return (StatusCode::UNAUTHORIZED, "Invalid or mismatched token").into_response(),
    };

    if let Err(r) = enforce_rate_limit(&state.limiter, "inbox_fetch", &addr, &claims.sub) {
        return r;
    }

    let tree = match state.db.open_tree("msg_queue") {
        Ok(t) => t,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let prefix = format!("queue:{}:", claims.sub);
    let now = chrono::Utc::now().timestamp();
    let mut messages = Vec::new();
    let mut to_delete = Vec::new();

    for item in tree.scan_prefix(prefix.as_bytes()) {
        if let Ok((key, value)) = item {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&value) {
                let expires = json["expires"].as_i64().unwrap_or(0);
                if now > expires {
                    to_delete.push(key);
                    continue;
                }
                messages.push(json["envelope"].clone());
                to_delete.push(key);
            }
        }
    }

    for key in to_delete {
        tree.remove(key).ok();
    }

    (StatusCode::OK, Json(serde_json::json!({ "messages": messages, "count": messages.len() }))).into_response()
}
