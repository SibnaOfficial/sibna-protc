//! NAT Traversal utilities for Sibna P2P.
//!
//! Provides UPnP port mapping and STUN public IP discovery.

use std::net::{SocketAddr, UdpSocket, IpAddr};
use std::time::Duration;
use tracing::info;

#[cfg(feature = "p2p")]
use igd::SearchOptions;
#[cfg(feature = "p2p")]
use stun::message::{Message as StunMessage, BINDING_REQUEST, AttrType, XOR_MAPPED_ADDRESS};
#[cfg(feature = "p2p")]
use stun::textattrs::XorMappedAddress;

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

    /// Discover public IP and reflexive address using STUN.
    ///
    /// Sends a Binding Request to `stun.l.google.com:19302` and parses the
    /// XOR-MAPPED-ADDRESS attribute from the response.
    async fn try_stun() -> P2pResult<SocketAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        
        let stun_server = "stun.l.google.com:19302";
        
        // Build STUN Binding Request
        let mut request = StunMessage::new();
        request.set_type(BINDING_REQUEST);
        let _ = request.build(&[]);
        let buf = request.marshal_binary()
            .map_err(|e| P2pError::InvalidMessage(format!("STUN encode: {}", e)))?;
        
        // Send request
        socket.send_to(&buf, stun_server)?;
        
        // Receive response
        let mut recv_buf = [0u8; 1024];
        let (size, src) = socket.recv_from(&mut recv_buf)?;
        
        // Verify response came from the expected STUN server (optional)
        if src.to_string() != stun_server {
            return Err(P2pError::InvalidMessage("STUN response from unexpected source".into()));
        }
        
        // Parse response
        let mut response = StunMessage::new();
        response.unmarshal_binary(&recv_buf[..size])
            .map_err(|e| P2pError::InvalidMessage(format!("STUN decode: {}", e)))?;
        
        // Extract XOR-MAPPED-ADDRESS attribute
        let xor_addr_attr = response.get_attr(AttrType::XorMappedAddress)
            .ok_or_else(|| P2pError::InvalidMessage("STUN response missing XOR-MAPPED-ADDRESS".into()))?;
        
        // Decode the attribute into a SocketAddr
        let xor_addr = XorMappedAddress::decode_from(&xor_addr_attr.value)
            .map_err(|e| P2pError::InvalidMessage(format!("STUN XOR-MAPPED-ADDRESS decode: {}", e)))?;
        
        let public_addr = xor_addr.get_addr()
            .map_err(|e| P2pError::InvalidMessage(format!("STUN address extraction: {}", e)))?;
        
        Ok(public_addr)
    }
}
