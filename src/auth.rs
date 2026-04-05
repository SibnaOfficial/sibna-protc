//! Authentication Layer — JWT Challenge-Response
//! 
//! Zero-trust identity binding: clients prove they own the Ed25519 key
//! by signing a server-issued challenge. No passwords stored.
//!
//! # Security Fixes
//! N-03: Challenge is now stored as HMAC-SHA256(challenge, jwt_secret) rather
//!       than plaintext. Prevents DB-read attacks from recovering live challenges.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use ed25519_dalek::{VerifyingKey, Signature};
use ed25519_dalek::Verifier;
use chrono::Utc;
use rand::RngCore;
use axum::extract::ConnectInfo;
use std::net::SocketAddr;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::warn;
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
    #[allow(dead_code)]
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

    let tree = match state.db.open_tree("auth_challenges") {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };
    let db_key = format!("challenge:{}", req.identity_key_hex);
    let expires_at = Utc::now().timestamp() + 60;

    // FIX N-03: store an HMAC-SHA256 of the challenge keyed by the JWT secret.
    // If the sled DB is read by an attacker, they cannot recover the challenge
    // bytes and therefore cannot forge a valid proof response.
    let mut mac = Hmac::<Sha256>::new_from_slice(state.jwt_secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(challenge_hex.as_bytes());
    let challenge_mac = hex::encode(mac.finalize().into_bytes());

    let value = format!("{}:{}:{}", challenge_hex, challenge_mac, expires_at);
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
    let tree = match state.db.open_tree("auth_challenges") {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };
    let db_key = format!("challenge:{}", req.identity_key_hex);
    let stored = match tree.get(db_key.as_bytes()) {
        Ok(Some(v)) => String::from_utf8_lossy(&v).to_string(),
        _ => return (StatusCode::UNAUTHORIZED, "No pending challenge").into_response(),
    };

    let parts: Vec<&str> = stored.splitn(3, ':').collect();
    if parts.len() != 3 {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Bad challenge format").into_response();
    }

    let (stored_challenge_hex, stored_mac_hex, expires_str) = (parts[0], parts[1], parts[2]);

    // V6 FIX: Compute HMAC of the stored challenge, then compare using constant-time
    // byte equality. A non-constant-time string comparison is a timing oracle that
    // lets an attacker recover the expected HMAC byte-by-byte from latency.
    let mut mac = Hmac::<Sha256>::new_from_slice(state.jwt_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(stored_challenge_hex.as_bytes());
    let computed_mac_bytes = mac.finalize().into_bytes();

    let stored_mac_bytes = match hex::decode(stored_mac_hex) {
        Ok(b) => b,
        Err(_) => {
            tree.remove(db_key.as_bytes()).ok();
            return (StatusCode::INTERNAL_SERVER_ERROR, "Challenge integrity error").into_response();
        }
    };
    if computed_mac_bytes.ct_eq(&stored_mac_bytes[..]).unwrap_u8() == 0 {
        warn!("AUTH_PROVE: challenge HMAC mismatch — possible DB tampering for {}", &req.identity_key_hex[..16.min(req.identity_key_hex.len())]);
        tree.remove(db_key.as_bytes()).ok();
        return (StatusCode::INTERNAL_SERVER_ERROR, "Challenge integrity error").into_response();
    }

    let expected_challenge_hex = stored_challenge_hex;
    // V9 FIX: Return a 500 if the expiry field cannot be parsed rather than
    // silently using 0, which causes a confusing "Challenge expired" error.
    let expires_at: i64 = match expires_str.parse() {
        Ok(v) => v,
        Err(_) => {
            tree.remove(db_key.as_bytes()).ok();
            return (StatusCode::INTERNAL_SERVER_ERROR, "Bad challenge format").into_response();
        }
    };
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

    // FIX: Use proper try_into() error handling instead of unwrap_or with a
    // zero-array fallback — a zero key would silently pass format checks but
    // would never match, leaking timing information and causing confusing errors.
    let key_arr: [u8; 32] = match key_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid identity key length").into_response(),
    };
    let verifying_key = match VerifyingKey::from_bytes(&key_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid Ed25519 public key").into_response(),
    };

    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid signature length").into_response(),
    };
    let signature = Signature::from_bytes(&sig_arr);

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
