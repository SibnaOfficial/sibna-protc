//! P2P Transport Layer for Sibna Protocol
//!
//! This module enables two peers to communicate directly without any central
//! server. The full Signal Protocol (X3DH + Double Ratchet) runs identically;
//! the only difference is that PreKey Bundles are exchanged in-band over a
//! direct TCP connection instead of via a server's REST API.
//!
//! # Feature gate
//! This module is only compiled when the `p2p` Cargo feature is enabled:
//! ```toml
//! sibna-core = { features = ["p2p"] }
//! ```
//!
//! # Quick start
//! ```rust,ignore
//! use sibna_core::p2p::{P2pNode, P2pConfig};
//! use sibna_core::{SecureContext, Config};
//!
//! // --- Responder (Bob) ---
//! let cfg = SecureContext::new(Config::default(), None)?;
//! let node = P2pNode::new(P2pConfig::default(), cfg).await?;
//! println!("Listening on {}", node.local_addr());
//! let peer = node.accept().await?; // blocks until Alice connects
//!
//! // --- Initiator (Alice) ---
//! let cfg2 = SecureContext::new(Config::default(), None)?;
//! let node2 = P2pNode::new(P2pConfig::default(), cfg2).await?;
//! let peer2 = node2.connect("127.0.0.1:PORT").await?;
//!
//! peer2.send_message(b"Hello Bob!").await?;
//! let msg = peer.recv_message().await?;
//! assert_eq!(msg, b"Hello Bob!");
//! ```

#[cfg(feature = "p2p")]
pub mod transport;
#[cfg(feature = "p2p")]
pub mod handshake;
#[cfg(feature = "p2p")]
pub mod peer;
#[cfg(feature = "p2p")]
pub mod node;
#[cfg(feature = "p2p")]
pub mod discovery;
#[cfg(feature = "p2p")]
pub mod nat;

#[cfg(feature = "p2p")]
pub use node::P2pNode;
#[cfg(feature = "p2p")]
pub use peer::Peer;
#[cfg(feature = "p2p")]
pub use discovery::{MdnsDiscovery, DiscoveredPeer};
#[cfg(feature = "p2p")]
pub use handshake::P2pHandshakeConfig;

use std::net::SocketAddr;

/// Configuration for a P2P node
#[derive(Clone, Debug)]
pub struct P2pConfig {
    /// Address to listen on.  Use `0.0.0.0:0` to let the OS assign a free port.
    pub bind_addr: SocketAddr,
    /// Max seconds to wait for a handshake to complete
    pub handshake_timeout_secs: u64,
    /// Max total connected peers; new connections are rejected beyond this
    pub max_peers: usize,
    /// Max message size in bytes (must match `sibna_core::Config::max_message_size`)
    pub max_message_size: usize,
    /// Whether to enable mDNS discovery for local networks
    pub enable_mdns: bool,
    /// Optional human-readable name for mDNS broadcasts
    pub node_name: Option<String>,
    /// Optional SOCKS5 proxy address for anonymous connections.
    ///
    /// Set to `Some("127.0.0.1:9050")` to route all outgoing connections
    /// through a local Tor daemon.
    ///
    /// **Requires Tor to be running on the specified address.**
    /// When set, DNS resolution is also performed by the proxy,
    /// preventing DNS leaks.
    pub proxy: Option<String>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().expect("static literal addr is always valid"),
            handshake_timeout_secs: 30,
            max_peers: 256,
            max_message_size: 10 * 1024 * 1024, // 10 MB
            enable_mdns: false,
            node_name: None,
            proxy: None, // direct connection by default; set to Some("127.0.0.1:9050") for Tor
        }
    }
}

/// Errors produced by the P2P layer
#[derive(Debug)]
pub enum P2pError {
    /// TCP / IO error
    Io(std::io::Error),
    /// Framing or serialisation error
    Framing(String),
    /// X3DH / Double Ratchet handshake error
    Handshake(String),
    /// Encryption / decryption error
    Crypto(String),
    /// Peer limit reached
    TooManyPeers,
    /// Operation timed out
    Timeout,
    /// Invalid message received from remote peer
    InvalidMessage(String),
    /// Peer disconnected
    Disconnected,
}

impl std::fmt::Display for P2pError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)              => write!(f, "I/O error: {}", e),
            Self::Framing(s)         => write!(f, "Framing error: {}", s),
            Self::Handshake(s)       => write!(f, "Handshake failed: {}", s),
            Self::Crypto(s)          => write!(f, "Crypto error: {}", s),
            Self::TooManyPeers       => write!(f, "Max peer limit reached"),
            Self::Timeout            => write!(f, "Operation timed out"),
            Self::InvalidMessage(s)  => write!(f, "Invalid message: {}", s),
            Self::Disconnected       => write!(f, "Peer disconnected"),
        }
    }
}

impl std::error::Error for P2pError {}

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<crate::error::ProtocolError> for P2pError {
    fn from(e: crate::error::ProtocolError) -> Self {
        Self::Crypto(e.to_string())
    }
}

/// Convenience Result type for P2P operations
pub type P2pResult<T> = Result<T, P2pError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2p_config_default() {
        let cfg = P2pConfig::default();
        assert_eq!(cfg.handshake_timeout_secs, 30);
        assert_eq!(cfg.max_peers, 256);
        assert_eq!(cfg.max_message_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_p2p_error_display() {
        let e = P2pError::Timeout;
        assert!(!e.to_string().is_empty());
        let io_err = P2pError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"));
        assert!(io_err.to_string().contains("I/O error"));
    }
}
