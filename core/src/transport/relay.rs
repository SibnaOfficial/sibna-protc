// ════════════════════════════════════════════════════════════════════════════
// FILE: core/src/transport/relay.rs - SECURITY HARDENED
// ════════════════════════════════════════════════════════════════════════════

//! Relay Transport — SOCKS5/Tor Anonymity v1.0.4 - SECURITY HARDENED
//!
//! The `RelayClient` connects to a Sibna Server via HTTP and WebSocket.
//! When a proxy is configured, all HTTP traffic is tunneled through SOCKS5.
//! 
//! SECURITY FIXES:
//! - FIX #1: No information leakage in InternalErrorDetailed (relay.rs line 32)
//! - FIX #2: No proxy error details exposed (relay.rs line 32)
//! - FIX #3: No HTTP client build error details exposed (relay.rs line 38)
//! - FIX #4: No network error details exposed (relay.rs lines 54, 74, 79)

use crate::ProtocolResult;
use crate::error::ProtocolError;
use reqwest::{Client, Proxy};
use url::Url;
use tracing::{info, warn, debug};

/// Sibna Relay Client with optional SOCKS5 proxy support.
pub struct RelayClient {
    server_url: Url,
    http_client: Client,
}

impl RelayClient {
    /// Create a new `RelayClient`.
    ///
    /// If `proxy_url_str` is provided (e.g. `"socks5://127.0.0.1:9050"` for Tor),
    /// all HTTP traffic from this client is tunneled through the proxy.
    /// 
    /// # Security
    /// - FIX #1, #2: Proxy errors don't leak details
    /// - FIX #3: HTTP client construction errors don't leak details
    pub fn new(server_url_str: &str, proxy_url_str: Option<&str>) -> ProtocolResult<Self> {
        let server_url = Url::parse(server_url_str)
            .map_err(|_| ProtocolError::InvalidMessage)?;

        let mut builder = Client::builder();

        if let Some(proxy_str) = proxy_url_str {
            info!("RelayClient: routing via proxy");
            // FIX #1: Don't expose proxy configuration errors
            let proxy = Proxy::all(proxy_str)
                .map_err(|e| {
                    warn!("RELAY_SECURITY: Proxy configuration failed");
                    debug!("Proxy error details: {}", e);
                    ProtocolError::InternalError  // ← NO details exposed
                })?;
            builder = builder.proxy(proxy);
        }

        // FIX #3: Don't expose HTTP client build errors
        let http_client = builder
            .build()
            .map_err(|e| {
                warn!("RELAY_SECURITY: HTTP client build failed");
                debug!("Client build error: {}", e);
                ProtocolError::InternalError  // ← NO details exposed
            })?;

        Ok(Self { server_url, http_client })
    }

    /// Upload a prekey bundle to the relay server.
    /// 
    /// # Security
    /// - FIX #4: Network errors don't leak details
    pub async fn upload_prekey_bundle(&self, identity_key_hex: &str, bundle_json: &str) -> ProtocolResult<()> {
        let url = self.server_url
            .join(&format!("/v1/prekeys/upload/{}", identity_key_hex))
            .map_err(|_| ProtocolError::InvalidMessage)?;

        let res = self.http_client
            .post(url)
            .body(bundle_json.to_string())
            .send()
            .await
            .map_err(|e| {
                warn!("RELAY_SECURITY: Prekey upload failed");
                debug!("Upload error: {}", e);
                ProtocolError::InternalError  // ← NO details exposed
            })?;

        if res.status().is_success() {
            info!("Prekey bundle uploaded");
            Ok(())
        } else {
            Err(ProtocolError::HandshakeFailed)
        }
    }

    /// Fetch a prekey bundle from the relay server.
    /// 
    /// # Security
    /// - FIX #4: Network errors don't leak details
    pub async fn fetch_prekey_bundle(&self, identity_key_hex: &str) -> ProtocolResult<String> {
        let url = self.server_url
            .join(&format!("/v1/prekeys/{}", identity_key_hex))
            .map_err(|_| ProtocolError::InvalidMessage)?;

        let res = self.http_client
            .get(url)
            .send()
            .await
            .map_err(|e| {
                warn!("RELAY_SECURITY: Prekey fetch failed");
                debug!("Fetch error: {}", e);
                ProtocolError::InternalError  // ← NO details exposed
            })?;

        if res.status().is_success() {
            res.text()
                .await
                .map_err(|e| {
                    warn!("RELAY_SECURITY: Response parsing failed");
                    debug!("Parse error: {}", e);
                    ProtocolError::InternalError  // ← NO details exposed
                })
        } else {
            Err(ProtocolError::HandshakeFailed)
        }
    }

    /// Returns the WebSocket URL for the relay endpoint.
    ///
    /// Use with any WebSocket client. The URL is derived from the server URL
    /// (http -> ws, https -> wss) and appended with `/ws`.
    pub fn websocket_url(&self, identity_key_hex: &str) -> ProtocolResult<String> {
        let mut ws_url = self.server_url.clone();
        let scheme = match ws_url.scheme() {
            "https" => "wss",
            _ => "ws",
        };
        ws_url
            .set_scheme(scheme)
            .map_err(|_| ProtocolError::InvalidMessage)?;
        ws_url.set_path(&format!("/ws/{}", identity_key_hex));
        Ok(ws_url.to_string())
    }
}
