//! Authentication Layer — JWT Challenge-Response
//! 
//! Zero-trust identity binding: clients prove they own the Ed25519 key
//! by signing a server-issued challenge. No passwords stored.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use ed25519_dalek::{VerifyingKey, Signature};
use ed25519_dalek::Verifier;
use chrono::Utc;
use rand::RngCore;
use axum::extract::ConnectInfo;
use std::net::SocketAddr;
use crate::{AppState, enforce_rate_limit};

/// JWT claims
#[derive(Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (identity key hex)
    pub sub: String,
    /// Issued at (unix seconds)
    pub iat: i64,
    /// Expiry (unix seconds)
    pub exp: i64,
    /// Device fingerprint
    pub device: String,
}

/// Request: register/get challenge
#[derive(Deserialize)]
pub struct RegisterRequest {
    /// Hex-encoded Ed25519 public key (32 bytes)
    pub identity_key_hex: String,
    /// Optional device label
    pub device_label: Option<String>,
}

/// Response to register
#[derive(Serialize)]
pub struct ChallengeResponse {
    /// Random 32-byte challenge (hex), client must sign with identity key
    pub challenge_hex: String,
    /// 60-second TTL
    pub expires_in: u64,
}

/// Request: prove challenge
#[derive(Deserialize)]
pub struct ProveRequest {
    pub identity_key_hex: String,
    pub challenge_hex: String,
    /// Ed25519 signature over challenge bytes (hex)
    pub signature_hex: String,
}

/// Response: JWT token
#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: u64,
}

/// POST /v1/auth/challenge — issue a random challenge
pub async fn challenge_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Rate limit the challenge endpoint
    if let Err(r) = enforce_rate_limit(&state.limiter, "auth_challenge", &addr, &req.identity_key_hex) {
        return r;
    }

    // Validate identity key length
    if req.identity_key_hex.len() != 64 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid identity_key length"}))).into_response();
    }

    // Generate 32-byte challenge
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    let challenge_hex = hex::encode(challenge);

    // Store with 60-second TTL (key: "challenge:{identity_key}")
    let tree = state.db.open_tree("auth_challenges").expect("db tree");
    let db_key = format!("challenge:{}", req.identity_key_hex);
    let expires_at = Utc::now().timestamp() + 60;
    let value = format!("{}:{}", challenge_hex, expires_at);
    tree.insert(db_key.as_bytes(), value.as_bytes()).ok();

    (StatusCode::OK, Json(ChallengeResponse {
        challenge_hex,
        expires_in: 60,
    })).into_response()
}

/// POST /v1/auth/prove — verify signature, issue JWT
pub async fn prove_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<ProveRequest>,
) -> impl IntoResponse {
    // Rate limit the prove endpoint
    if let Err(r) = enforce_rate_limit(&state.limiter, "auth_prove", &addr, &req.identity_key_hex) {
        return r;
    }

    // 1. Look up the challenge
    let tree = state.db.open_tree("auth_challenges").expect("db tree");
    let db_key = format!("challenge:{}", req.identity_key_hex);
    let stored = match tree.get(db_key.as_bytes()) {
        Ok(Some(v)) => String::from_utf8_lossy(&v).to_string(),
        _ => return (StatusCode::UNAUTHORIZED, "No pending challenge").into_response(),
    };

    let parts: Vec<&str> = stored.splitn(2, ':').collect();
    if parts.len() != 2 {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Bad challenge format").into_response();
    }

    let (expected_challenge_hex, expires_str) = (parts[0], parts[1]);
    let expires_at: i64 = expires_str.parse().unwrap_or(0);
    if Utc::now().timestamp() > expires_at {
        tree.remove(db_key.as_bytes()).ok();
        return (StatusCode::UNAUTHORIZED, "Challenge expired").into_response();
    }

    // 2. Verify the challenge matches what was sent
    if req.challenge_hex != expected_challenge_hex {
        return (StatusCode::UNAUTHORIZED, "Challenge mismatch").into_response();
    }

    // 3. Decode identity key and signature
    let key_bytes = match hex::decode(&req.identity_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, "Invalid identity_key hex").into_response(),
    };

    let sig_bytes = match hex::decode(&req.signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, "Invalid signature hex").into_response(),
    };

    let verifying_key = match VerifyingKey::from_bytes(key_bytes.as_slice().try_into().unwrap_or(&[0u8; 32])) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid Ed25519 public key").into_response(),
    };

    let signature = match Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap_or(&[0u8; 64])) {
        sig => sig,
    };

    let challenge_bytes = match hex::decode(&req.challenge_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid challenge hex").into_response(),
    };

    if verifying_key.verify(&challenge_bytes, &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, "Signature verification failed").into_response();
    }

    // 4. Invalidate challenge (one-time use)
    tree.remove(db_key.as_bytes()).ok();

    // 5. Issue JWT (24h expiry)
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: req.identity_key_hex.clone(),
        iat: now,
        exp: now + 86400,
        device: "default".to_string(),
    };

    let secret = state.jwt_secret.as_bytes();
    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret)) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to issue token").into_response(),
    };

    (StatusCode::OK, Json(TokenResponse {
        token,
        expires_in: 86400,
    })).into_response()
}

/// Validate a Bearer token from Authorization header
pub fn validate_jwt(token: &str, secret: &str) -> Option<Claims> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .ok()
        .map(|d| d.claims)
}
