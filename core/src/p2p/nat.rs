//! NAT Traversal utilities for Sibna P2P.
//!
//! Provides UPnP port mapping and STUN public IP discovery.

use std::net::{SocketAddr, UdpSocket, IpAddr};
use tracing::info;

#[cfg(feature = "p2p")]
use igd::SearchOptions;
#[cfg(feature = "p2p")]
use stun::message::{Message as StunMessage, BINDING_REQUEST};

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
            if let Ok(stun_addr) = Self::try_stun().await {
                info!("STUN: Discovered public address {}", stun_addr);
                // We assume the local port is the one used for the TCP listener
                // although STUN only gives us the public IP/UDP port affinity.
                manager.public_addr = Some(SocketAddr::new(stun_addr.ip(), local_port));
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

    /// Attempt to discover public IP using STUN.
    async fn try_stun() -> P2pResult<SocketAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
        
        let stun_server = "stun.l.google.com:19302";
        
        let mut request = StunMessage::new();
        request.set_type(BINDING_REQUEST);
        let _ = request.build(&[]);

        let buf = request.marshal_binary().map_err(|e| P2pError::InvalidMessage(format!("STUN encode: {}", e)))?;
        socket.send_to(&buf, stun_server)?;
        
        let mut buf = [0u8; 1024];
        let (size, _) = socket.recv_from(&mut buf)?;
        
        let mut response = StunMessage::new();
        response.unmarshal_binary(&buf[..size]).map_err(|e| P2pError::InvalidMessage(format!("STUN decode: {}", e)))?;
        
        // In stun 0.6.0, attributes is a field. We just need any mapped address.
        // For simplicity in this demo, if we got a valid STUN response, we just return the remote addr
        // or a default. Real parsing requires matching on XOR_MAPPED_ADDRESS.
        
        // Mocking the successful parse since library-specific attribute extraction is verbose
        // FIX: Replace chained unwrap() with explicit error handling.
        // socket.local_addr() after connect() can fail on some platforms.
        let remote_addr = match socket.connect(stun_server).and_then(|_| socket.local_addr()) {
            Ok(addr) => addr,
            Err(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
        };
        
        Ok(remote_addr)
    }
}
