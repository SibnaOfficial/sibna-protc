//! Relay Transport — SOCKS5/Tor Anonymity v1.0.3
//!
//! The `RelayClient` connects to a Sibna Server via HTTP and WebSocket.
//! When a proxy is configured, all HTTP traffic is tunneled through SOCKS5.

use crate::ProtocolResult;
use crate::error::ProtocolError;
use reqwest::{Client, Proxy};
use url::Url;
use tracing::info;

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
    pub fn new(server_url_str: &str, proxy_url_str: Option<&str>) -> ProtocolResult<Self> {
        let server_url = Url::parse(server_url_str)
            .map_err(|_| ProtocolError::InvalidMessage)?;

        let mut builder = Client::builder();

        if let Some(proxy_str) = proxy_url_str {
            info!("RelayClient: routing via SOCKS5 proxy at {}", proxy_str);
            let proxy = Proxy::all(proxy_str)
                .map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;
            builder = builder.proxy(proxy);
        }

        let http_client = builder
            .build()
            .map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;

        Ok(Self { server_url, http_client })
    }

    /// Upload a prekey bundle to the relay server.
    pub async fn upload_prekey_bundle(&self, identity_key_hex: &str, bundle_json: &str) -> ProtocolResult<()> {
        let url = self.server_url
            .join(&format!("/v1/prekeys/upload/{}", identity_key_hex))
            .map_err(|_| ProtocolError::InvalidMessage)?;

        let res = self.http_client
            .post(url)
            .body(bundle_json.to_string())
            .send()
            .await
            .map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;

        if res.status().is_success() {
            info!("Prekey bundle uploaded for {}", &identity_key_hex[..16.min(identity_key_hex.len())]);
            Ok(())
        } else {
            Err(ProtocolError::HandshakeFailed)
        }
    }

    /// Fetch a prekey bundle from the relay server.
    pub async fn fetch_prekey_bundle(&self, identity_key_hex: &str) -> ProtocolResult<String> {
        let url = self.server_url
            .join(&format!("/v1/prekeys/{}", identity_key_hex))
            .map_err(|_| ProtocolError::InvalidMessage)?;

        let res = self.http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;

        if res.status().is_success() {
            res.text()
                .await
                .map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })
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
        // set_scheme may fail for some edge cases; we propagate it as InvalidMessage
        ws_url
            .set_scheme(scheme)
            .map_err(|_| ProtocolError::InvalidMessage)?;
        ws_url.set_path(&format!("/ws/{}", identity_key_hex));
        Ok(ws_url.to_string())
    }
}
