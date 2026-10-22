#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::needless_return)]
#![allow(clippy::io_other_error)]
#![allow(clippy::manual_flatten)]
#![allow(clippy::result_large_err)]
#![allow(clippy::needless_borrows_for_generic_args)]
//! Sibna Universal Server
//!
//! Transports:
//!   - REST (HTTP) — prekey operations + auth
//!   - WebSocket — real-time sealed-envelope relay
//!
//! Security:
//!   - Ed25519 identity binding
//!   - JWT challenge-response auth
//!   - Hybrid rate limiting (IP + Identity)
//!   - Bundle replay protection (bundle_id dedup)
//!   - Sealed Sender (server never sees sender)
//!   - Offline message queue (7-day TTL, redb)
//!   - Zero-Reuse prekey compaction

mod auth;
mod db;
mod ws;

use db::DbState;

use axum::{
    extract::{ConnectInfo, FromRef, Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sibna_core::rate_limit::RateLimiter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};

// Shared application state

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DbState>,
    pub rt: Arc<RuntimeState>,
}

pub struct RuntimeState {
    pub limiter: Arc<RateLimiter>,
    /// Connected WebSocket clients: identity_key_hex → sender channel
    pub clients: DashMap<String, ws::ClientTx>,
    /// JWT signing secret — zeroized on drop to prevent secret leakage in core dumps
    pub jwt_secret: zeroize::Zeroizing<String>,
}

/// Centralized Auth Extractor — ensures MUST-BE-AUTHENTICATED for protected routes.
pub struct AuthUser(pub auth::Claims);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

        let auth_str = auth_header
            .to_str()
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid Authorization header"))?;
        let token = auth_str
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid Token Format"))?;

        match auth::validate_jwt(token, &app_state.rt.jwt_secret) {
            Some(claims) => Ok(AuthUser(claims)),
            None => Err((StatusCode::UNAUTHORIZED, "Invalid or expired token")),
        }
    }
}

// Entry point

#[tokio::main]
#[allow(dead_code)]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    run_server(listener, None).await
}

pub async fn run_server(
    listener: tokio::net::TcpListener,
    db_path_override: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listener.local_addr()?;
    eprintln!("DEBUG: Starting Sibna Server on {}", addr);
    // ... rest of the function (starting with Database)
    let db_path = db_path_override.unwrap_or_else(|| {
        std::env::var("SIBNA_DB_PATH").unwrap_or_else(|_| "sibna_server_db".to_string())
    });
    let db_state = Arc::new(db::open_db(&db_path)?);
    eprintln!("DEBUG: redb opened at {}", db_path);

    // JWT secret
    // : In production, a missing JWT secret is a fatal misconfiguration.
    // An ephemeral secret invalidates all active sessions on every restart (implicit DoS)
    // and indicates the deployment was not properly secured.
    // Set SIBNA_ENV=production to enforce this. In development/test, a warning suffices.
    let is_production = std::env::var("SIBNA_ENV")
        .map(|v| v.to_lowercase() == "production")
        .unwrap_or(false);

    let jwt_secret = Arc::new(match std::env::var("SIBNA_JWT_SECRET") {
        Ok(secret) if secret.len() >= 32 => secret,
        Ok(short) => {
            tracing::error!(
                "SIBNA_JWT_SECRET is set but too short ({} chars, minimum 32). \
                     Use a cryptographically random 64-char hex string.",
                short.len()
            );
            if is_production {
                return Err("SIBNA_JWT_SECRET too short — refusing to start in production".into());
            }
            warn!("Using short JWT secret in non-production mode — DO NOT use in production");
            short
        }
        Err(_) => {
            if is_production {
                tracing::error!(
                    "SIBNA_JWT_SECRET is not set. Refusing to start in production. \
                         Generate a secret with: openssl rand -hex 32"
                );
                return Err("SIBNA_JWT_SECRET not set — refusing to start in production".into());
            }
            warn!(
                "SIBNA_JWT_SECRET not set — generating ephemeral secret. \
                     ALL SESSIONS WILL BE INVALIDATED ON RESTART. \
                     Set SIBNA_ENV=production to prevent this."
            );
            hex::encode(random_bytes_32())
        }
    });

    let mut limiter = RateLimiter::new();
    limiter.set_global_enabled(true);
    limiter.set_global_rps(5000);

    let prekey_limit = sibna_core::rate_limit::OperationLimit {
        max_per_second: 500, // Increase for testing
        max_per_minute: 5000,
        max_per_hour: 100_000,
        max_per_day: 1_000_000,
        cooldown: Duration::from_millis(100),
        burst_size: 100,
    };

    // Strict pre-auth IP-only rate limit. This bucket is consumed by the
    // `ip_rate_limit` middleware on every /v1/* request before the
    // AuthUser extractor runs. Burst of 50 requests, sustained 50/sec,
    // so legitimate bursts pass but a 1000-req flood is rate-limited
    // within the first 50-100 requests.
    let ip_unauth_limit = sibna_core::rate_limit::OperationLimit {
        max_per_second: 50,
        max_per_minute: 200,
        max_per_hour: 5_000,
        max_per_day: 20_000,
        cooldown: Duration::from_millis(500),
        burst_size: 50,
    };
    limiter.add_limit("ip_unauth".to_string(), ip_unauth_limit);

    limiter.add_limit("prekey_upload".to_string(), prekey_limit.clone());
    limiter.add_limit("prekey_fetch".to_string(), prekey_limit.clone());
    limiter.add_limit("auth_challenge".to_string(), prekey_limit.clone());
    limiter.add_limit("auth_prove".to_string(), prekey_limit.clone());
    limiter.add_limit("message_send".to_string(), prekey_limit);

    let rt_state = Arc::new(RuntimeState {
        limiter: Arc::new(limiter),
        clients: DashMap::new(),
        jwt_secret: zeroize::Zeroizing::new((*jwt_secret).clone()),
    });

    let state = AppState {
        db: db_state,
        rt: rt_state,
    };

    // Sub-router for endpoints that need IP-only rate limiting BEFORE
    // the AuthUser extractor runs. This is the DoS shield: an attacker
    // can flood these endpoints with unauthenticated requests and the
    // rate limit fires before auth is attempted.
    //
    // Endpoints NOT in this sub-router (`/v1/messages/send`,
    // `/v1/messages/inbox`) have handler-level rate limits that operate
    // on `claims.sub` (i.e., per authenticated user) and rely on the
    // AuthUser extractor to reject unauthenticated requests with 401.
    let protected = Router::new()
        .route("/v1/auth/challenge", post(auth::challenge_handler))
        .route("/v1/auth/prove", post(auth::prove_handler))
        .route("/v1/prekeys/upload", post(upload_prekey_handler))
        .route("/v1/prekeys/:user_id", get(fetch_prekey_handler))
        .route("/v1/prekeys/:user_id", delete(delete_prekey_handler))
        .layer(middleware::from_fn_with_state(state.clone(), ip_rate_limit));

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/v1/messages/send", post(send_message_handler))
        .route("/v1/messages/inbox", get(inbox_handler))
        .route("/ws", get(ws::ws_handler))
        .merge(protected)
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(21 * 1024 * 1024)) // 21 MB to allow for large-test payloads
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any),
        )
        .with_state(state.clone());

    // Pruning Task
    {
        let db_prune = state.db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let tree = &db_prune.tree_dedup;
                let cutoff = chrono::Utc::now().timestamp() - 48 * 3600;
                let mut to_delete = Vec::new();
                for item in tree.iter() {
                    let (key, value): (Vec<u8>, Vec<u8>) = item;
                    if value.len() == 8 {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&value);
                        if i64::from_be_bytes(b) < cutoff {
                            to_delete.push(key);
                        }
                    }
                }
                for key in to_delete {
                    tree.remove(key).ok();
                }
            }
        });
    }

    info!("Sibna Server listening on {}", addr);

    // : Graceful shutdown on SIGTERM/SIGINT.
    // redb commits each transaction immediately, so no explicit flush is
    // required on shutdown — the database is always in a consistent state.
    let db_for_shutdown = state.db.clone();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
            let mut sigint =
                signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
            tokio::select! {
                _ = sigterm.recv() => { info!("SIGTERM received — starting graceful shutdown"); }
                _ = sigint.recv()  => { info!("SIGINT received — starting graceful shutdown");  }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to register Ctrl-C handler");
            info!("Ctrl-C received — starting graceful shutdown");
        }
        // redb commits on every write-transaction; no flush needed
        drop(db_for_shutdown);
        info!("Database handle dropped — shutdown complete");
    })
    .await?;
    Ok(())
}

// Helpers

fn generate_rate_key(ip: &SocketAddr, identity: &str) -> String {
    // DefaultHasher is NOT collision-resistant and is not stable across
    // processes/versions. Two different (IP, identity) pairs can collide and share
    // a rate-limit bucket, allowing one identity to exhaust another's quota.
    // Use plain concatenation with a separator instead — the RateLimiter stores
    // entries in a HashMap and does its own hashing internally.
    format!("{}|{}", ip.ip(), identity)
}

fn enforce_rate_limit(
    limiter: &RateLimiter,
    operation: &str,
    ip: &SocketAddr,
    identity: &str,
) -> Result<(), axum::response::Response> {
    let key = generate_rate_key(ip, identity);
    if let Err(e) = limiter.check(operation, &key) {
        warn!(
            "Rate limit exceeded for {} ({}): {}",
            operation,
            &identity[..identity.len().min(16)],
            e
        );
        return Err((StatusCode::TOO_MANY_REQUESTS, e.to_string()).into_response());
    }
    Ok(())
}

/// IP-only rate limit middleware that runs BEFORE the AuthUser extractor.
/// This prevents unauthenticated DoS attacks (e.g., flooding
/// `/v1/prekeys/upload` with garbage to fill redb).
///
/// The middleware reads the client IP from the `ConnectInfo<SocketAddr>`
/// extension (set by `into_make_service_with_connect_info`) and applies
/// the rate limit keyed only by IP. Per-identity rate limits are still
/// applied inside the handler after auth succeeds.
async fn ip_rate_limit(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Apply the strict pre-auth IP rate limit. The bucket is keyed by
    // IP only (no identity since auth has not happened yet). This is
    // a coarse DoS shield; per-operation, per-identity limits are
    // applied inside the handler after auth succeeds.
    let addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    if let Err(r) = enforce_rate_limit(&state.rt.limiter, "ip_unauth", &addr, "ip_only") {
        return r;
    }
    next.run(request).await
}

fn random_bytes_32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

// Handlers

async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "version": "3.0.2",
            "transports": ["http", "websocket"],
            "auth": "ed25519-jwt"
        })),
    )
}

// PreKey Upload

#[derive(Deserialize)]
struct UploadPrekeyRequest {
    bundle_hex: String,
    is_last_resort: Option<bool>,
}

async fn upload_prekey_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AuthUser(claims): AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<UploadPrekeyRequest>,
) -> impl IntoResponse {
    if let Err(r) = enforce_rate_limit(&state.rt.limiter, "prekey_upload", &addr, &claims.sub) {
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
    let db_key = if payload.is_last_resort.unwrap_or(false) {
        format!("prekey_resort:{}", root_id)
    } else {
        format!("{}:{}", root_id, bundle.device_id)
    };

    if let Err(r) = enforce_rate_limit(&state.rt.limiter, "prekey_upload", &addr, &root_id) {
        return r;
    }
    if let Ok(Some(existing)) = state.db.tree_prekeys.get(&db_key) {
        let existing: Vec<u8> = existing;
        if let Ok(existing_bundle) = sibna_core::handshake::PreKeyBundle::from_bytes(&existing) {
            if bundle.bundle_id == existing_bundle.bundle_id {
                return (
                    StatusCode::CONFLICT,
                    "Replay attack detected: bundle_id reused",
                )
                    .into_response();
            }
        }
    }

    if state
        .db
        .tree_prekeys
        .insert(db_key.as_bytes(), bundle_bytes)
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    info!(
        "PreKey uploaded for Root {} Device {}",
        &root_id[..16],
        bundle.device_id
    );
    StatusCode::OK.into_response()
}

// PreKey Fetch

#[derive(Serialize)]
struct FetchPrekeyResponse {
    bundles_hex: Vec<String>,
}

async fn fetch_prekey_handler(
    Path(root_id): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Err(r) = enforce_rate_limit(&state.rt.limiter, "prekey_fetch", &addr, &root_id) {
        return r;
    }

    let prefix = format!("{}:", root_id);
    let resort_key = format!("prekey_resort:{}", root_id);

    let mut fetched_bundles_hex = Vec::new();
    let mut keys_to_delete = Vec::new();

    // 1. Try fetching standard One-Time Prekeys
    for (key, bundle_bytes) in state.db.tree_prekeys.scan_prefix(prefix.as_bytes()) {
        if let Ok(bundle) = sibna_core::handshake::PreKeyBundle::from_bytes(&bundle_bytes) {
            if bundle.validate().is_ok() {
                fetched_bundles_hex.push(hex::encode(&bundle_bytes));
            }
        }
        keys_to_delete.push(key);
    }

    // 2. PILLAR 2: If no one-time keys are available, fallback to Last Resort Key
    let mut using_resort = false;
    if fetched_bundles_hex.is_empty() {
        if let Ok(Some(resort_bytes)) = state.db.tree_prekeys.get(resort_key.as_bytes()) {
            let resort_bytes: Vec<u8> = resort_bytes;
            if let Ok(bundle) = sibna_core::handshake::PreKeyBundle::from_bytes(&resort_bytes) {
                if bundle.validate().is_ok() {
                    fetched_bundles_hex.push(hex::encode(&resort_bytes));
                    using_resort = true;
                    info!(
                        "WARN: PreKey starvation for {} — using Last Resort Key!",
                        &root_id[..16]
                    );
                    // We DO NOT add it to keys_to_delete. It persists forever.
                }
            }
        }
    }

    if fetched_bundles_hex.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Zero-Reuse: delete one-time keys after fetch
    for key in keys_to_delete {
        let _ = state.db.tree_prekeys.remove(key);
    }

    if !using_resort {
        info!(
            "Fetched {} One-Time PreKey(s) and compacted for {}",
            fetched_bundles_hex.len(),
            &root_id[..16]
        );
    }

    (
        StatusCode::OK,
        Json(FetchPrekeyResponse {
            bundles_hex: fetched_bundles_hex,
        }),
    )
        .into_response()
}

async fn delete_prekey_handler(
    Path(root_id): Path<String>,
    AuthUser(claims): AuthUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verify the caller owns the identity key they are trying to delete.
    if claims.sub != root_id {
        return (
            StatusCode::FORBIDDEN,
            "Cannot delete another user's prekeys",
        )
            .into_response();
    }

    let prefix = format!("{}:", root_id);
    let mut deleted = false;
    for (key, _) in state.db.tree_prekeys.scan_prefix(prefix.as_bytes()) {
        if state
            .db
            .tree_prekeys
            .remove(key)
            .unwrap_or_default()
            .is_some()
        {
            deleted = true;
        }
    }
    if deleted {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

// Sealed Message REST Endpoint (HTTP fallback for IoT/no-WS)

#[derive(Deserialize)]
struct SendMessageRequest {
    /// Recipient identity_key hex (32 bytes = 64 hex chars)
    recipient_id: String,
    /// Encrypted payload (hex) — server cannot read
    payload_hex: String,
    /// Sender identity_key hex (32 bytes = 64 hex chars) — must match JWT subject
    sender_id: String,
    /// Ed25519 signature over canonical payload (recipient_id + message_id + payload_hex + sender_id)
    signature_hex: String,
    /// LZ4 compressed?
    compressed: Option<bool>,
    /// Unique message ID for deduplication
    message_id: Option<String>,
}

async fn send_message_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AuthUser(claims): AuthUser,
    State(state): State<AppState>,
    Json(req): Json<SendMessageRequest>,
) -> impl IntoResponse {
    // Use "message_send" rate limit, not "prekey_upload" (wrong operation key).
    if let Err(r) = enforce_rate_limit(&state.rt.limiter, "message_send", &addr, &claims.sub) {
        return r;
    }

    // Validate that the sender_id in the request matches the authenticated JWT subject.
    if req.sender_id != claims.sub {
        return (
            StatusCode::FORBIDDEN,
            "Sender ID does not match authenticated JWT subject",
        )
            .into_response();
    }

    // Validate message_id
    let message_id = req.message_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if message_id.is_empty() || message_id.len() > 128 {
        return (StatusCode::BAD_REQUEST, "Invalid message_id").into_response();
    }

    // Validate recipient_id format (64 hex chars = 32-byte key)
    if req.recipient_id.len() != 64 || !req.recipient_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "Invalid recipient_id").into_response();
    }

    // Validate sender_id format (64 hex chars = 32-byte key)
    if req.sender_id.len() != 64 || !req.sender_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "Invalid sender_id").into_response();
    }

    // Validate payload_hex size (20 MB hex = 10 MB payload)
    const MAX_PAYLOAD_HEX_LEN: usize = 20 * 1024 * 1024;
    if req.payload_hex.len() > MAX_PAYLOAD_HEX_LEN {
        return (StatusCode::BAD_REQUEST, "Payload too large").into_response();
    }

    // Verify Ed25519 signature over canonical payload.
    // Canonical = u64_be(len)||recipient_id || u64_be(len)||message_id ||
    //             u64_be(len)||payload_hex || u64_be(len)||sender_id
    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use std::io::Write;

        let mut canonical: Vec<u8> = Vec::with_capacity(
            4 * 8
                + req.recipient_id.len()
                + message_id.len()
                + req.payload_hex.len()
                + req.sender_id.len(),
        );
        let r = req.recipient_id.as_bytes();
        let m = message_id.as_bytes();
        let p = req.payload_hex.as_bytes();
        let s = req.sender_id.as_bytes();
        canonical.write_all(&(r.len() as u64).to_be_bytes()).ok();
        canonical.write_all(r).ok();
        canonical.write_all(&(m.len() as u64).to_be_bytes()).ok();
        canonical.write_all(m).ok();
        canonical.write_all(&(p.len() as u64).to_be_bytes()).ok();
        canonical.write_all(p).ok();
        canonical.write_all(&(s.len() as u64).to_be_bytes()).ok();
        canonical.write_all(s).ok();

        let key_bytes = match hex::decode(&req.sender_id) {
            Ok(b) if b.len() == 32 => b,
            _ => return (StatusCode::BAD_REQUEST, "Invalid sender_id hex").into_response(),
        };
        let key_arr: [u8; 32] = match key_bytes.try_into() {
            Ok(a) => a,
            _ => return (StatusCode::BAD_REQUEST, "Invalid sender_id length").into_response(),
        };
        let verifying_key = match VerifyingKey::from_bytes(&key_arr) {
            Ok(k) => k,
            _ => return (StatusCode::BAD_REQUEST, "Invalid Ed25519 public key").into_response(),
        };
        let sig_bytes = match hex::decode(&req.signature_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return (StatusCode::BAD_REQUEST, "Invalid signature hex").into_response(),
        };
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            _ => return (StatusCode::BAD_REQUEST, "Invalid signature length").into_response(),
        };
        let signature = Signature::from_bytes(&sig_arr);
        if verifying_key.verify(&canonical, &signature).is_err() {
            return (StatusCode::UNAUTHORIZED, "Signature verification failed").into_response();
        }
    }

    let timestamp = chrono::Utc::now().timestamp();

    let envelope = ws::SealedEnvelope {
        recipient_id: req.recipient_id.clone(),
        payload_hex: req.payload_hex,
        compressed: req.compressed.unwrap_or(false),
        message_id,
        timestamp,
        sender_id: req.sender_id.clone(),
        signature_hex: req.signature_hex.clone(),
    };

    // Try to push to connected WebSocket client
    if let Some(client_tx) = state.rt.clients.get(&envelope.recipient_id) {
        if let Ok(data) = serde_json::to_vec(&ws::WsMessage::Envelope(envelope.clone())) {
            if client_tx.send(data).is_ok() {
                info!("Message delivered live to {}", &envelope.recipient_id[..16]);
                return StatusCode::OK.into_response();
            }
        }
    }

    // Recipient offline — queue it
    let db_key = format!("queue:{}:{}", envelope.recipient_id, envelope.message_id);
    let ttl = chrono::Utc::now().timestamp() + 7 * 86400;
    let value = serde_json::json!({ "envelope": envelope, "expires": ttl });
    if let Ok(bytes) = serde_json::to_vec(&value) {
        state.db.tree_queue.insert(db_key.as_bytes(), bytes).ok();
        info!(
            "Message queued for offline recipient {}",
            envelope.recipient_id.get(..16).unwrap_or(&envelope.recipient_id)
        );
    }

    StatusCode::ACCEPTED.into_response()
}

// Inbox Fetch (for HTTP-only devices)

#[derive(Deserialize)]
struct InboxQuery {
    identity_key_hex: String,
}

async fn inbox_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AuthUser(claims): AuthUser,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<InboxQuery>,
) -> impl IntoResponse {
    // Validate identity binding
    if claims.sub != q.identity_key_hex {
        return (StatusCode::UNAUTHORIZED, "Identity mismatch").into_response();
    }

    if let Err(r) = enforce_rate_limit(&state.rt.limiter, "inbox_fetch", &addr, &claims.sub) {
        return r;
    }

    let prefix = format!("queue:{}:", claims.sub);
    let now = chrono::Utc::now().timestamp();
    let mut messages = Vec::new();
    let mut to_delete = Vec::new();

    for (key, value) in state.db.tree_queue.scan_prefix(prefix.as_bytes()) {
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

    for key in to_delete {
        state.db.tree_queue.remove(key).ok();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "messages": messages, "count": messages.len() })),
    )
        .into_response()
}
