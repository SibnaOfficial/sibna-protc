//! Relay Transport Architecture — SOCKS5/Tor Anonymity v2.0.0
//!
//! This module implements the `RelayClient`, the primary transport layer
//! for communicating with a Sibna Server. It supports:
//! 
//! 1. **RESTful Prekey Sync**: HTTP uploading/fetching of hybrid bundles.
//! 2. **WebSocket Relay**: Real-time bi-directional message relay.
//! 3. **Tor/Proxy Anonymity**: Optional SOCKS5 tunneling for all traffic.

#[cfg(feature = "p2p")]
pub mod relay;

#[cfg(feature = "p2p")]
pub use relay::RelayClient;
