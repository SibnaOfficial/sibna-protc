//! NAT Traversal utilities for Sibna P2P.
//!
//! Provides UPnP port mapping and STUN public IP discovery.

use std::net::{SocketAddr, IpAddr};
use tracing::info;

#[cfg(feature = "p2p")]
use igd::SearchOptions;

use super::{P2pResult, P2pError};

/// Manages NAT traversal for the local P2P node.
pub struct NatManager {
    /// The public address discovered via STUN/UPnP
    pub public_addr: Option<SocketAddr>,
    /// Whether UPnP successfully mapped a port
    pub upnp_mapped: bool,
}

impl NatManager {
    /// Create a new NatManager and attempt to discover public connectivity.
    pub async fn new(local_port: u16) -> Self {
        let mut manager = Self {
            public_addr: None,
            upnp_mapped: false,
        };

        // 1. Try UPnP mapping first
        if let Ok(mapped_addr) = Self::try_upnp(local_port) {
            info!("UPnP: Successfully mapped port {} to {}", local_port, mapped_addr);
            manager.public_addr = Some(mapped_addr);
            manager.upnp_mapped = true;
        }

        // 2. If UPnP failed or to verify, try STUN
        if manager.public_addr.is_none() {
            match Self::try_stun().await {
                Ok(stun_addr) => {
                    info!("STUN: Discovered public address {}", stun_addr);
                    // Use the discovered IP with the original local port (TCP listener port)
                    manager.public_addr = Some(SocketAddr::new(stun_addr.ip(), local_port));
                }
                Err(e) => {
                    tracing::debug!("STUN discovery failed: {}", e);
                }
            }
        }

        manager
    }

    /// Attempt to map a port using UPnP.
    fn try_upnp(local_port: u16) -> P2pResult<SocketAddr> {
        let gateway = igd::search_gateway(SearchOptions::default())
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        
        let local_addr = if_addrs::get_if_addrs()?.into_iter()
            .find(|iface| !iface.is_loopback() && matches!(iface.addr, if_addrs::IfAddr::V4(_)))
            .map(|iface| iface.addr.ip())
            .ok_or_else(|| P2pError::InvalidMessage("No local IPv4 address found for UPnP".into()))?;

        let local_v4 = match local_addr {
            IpAddr::V4(addr) => addr,
            _ => return Err(P2pError::InvalidMessage("IPv6 not supported for UPnP yet".into())),
        };
        let local_socket = std::net::SocketAddrV4::new(local_v4, local_port);
        
        gateway.add_any_port(igd::PortMappingProtocol::TCP, local_socket, 0, "Sibna-P2P")
            .map(|ext_port| {
                let ext_ip = gateway.get_external_ip().unwrap_or(local_v4);
                SocketAddr::new(IpAddr::V4(ext_ip), ext_port)
            })
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))
    }

    async fn try_stun() -> P2pResult<SocketAddr> {
        tracing::debug!("STUN discovery is temporarily disabled due to crate version mismatch.");
        Err(P2pError::InvalidMessage("STUN disabled".into()))
    }
}
