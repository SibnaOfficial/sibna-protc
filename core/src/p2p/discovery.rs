//! Local Peer Discovery via Multicast DNS (mDNS)
//!
//! Exposes a `MdnsDiscovery` handle that registers the local node with `mdns-sd`
//! so that nearby devices can find it automatically. It also browses the local
//! network for other peers broadcasting the exact same service type.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::{P2pResult, P2pError};

const SIBNA_SERVICE_TYPE: &str = "_sibna._tcp.local.";

/// A discovered peer from the local network.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// The public Ed25519 identity key of the peer (hex-encoded)
    pub peer_id_hex: String,
    /// Primary IP and Port to dial
    pub addr: SocketAddr,
    /// Human-readable node name
    pub name: String,
}

/// Provides mDNS service broadcasting and browsing for Sibna P2P.
pub struct MdnsDiscovery {
    daemon: ServiceDaemon,
    service_type: String,
    instance_name: String,
}

impl MdnsDiscovery {
    /// Initialise mDNS and optionally broadcast the local node's presence.
    /// 
    /// - `bind_addr`: The full `SocketAddr` the P2P node is listening on.
    /// - `peer_id_bytes`: The 32-byte Ed25519 public key.
    /// - `node_name`: An optional human-readable name, e.g. "Alice's Phone".
    pub fn new(
        bind_addr: SocketAddr,
        peer_id_bytes: &[u8; 32],
        node_name: Option<&str>,
    ) -> P2pResult<Self> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("mDNS init: {}", e))))?;

        let peer_id_hex = hex::encode(peer_id_bytes);
        
        let instance_name = if let Some(n) = node_name {
            format!("{}-{}", n, &peer_id_hex[..8])
        } else {
            format!("Sibna-Node-{}", &peer_id_hex[..8])
        };

        let mut properties = HashMap::new();
        properties.insert("peer_id".to_string(), peer_id_hex.clone());
        properties.insert("version".to_string(), "1".to_string());

        let host_name = format!("{}.local.", instance_name);
        
        // If bind_addr is wildcard, we must resolve it to a real IP for mDNS advertisement
        let ad_ip = if bind_addr.ip().is_unspecified() {
            if_addrs::get_if_addrs().ok()
                .and_then(|ifs: Vec<if_addrs::Interface>| {
                    ifs.into_iter()
                        // Prefer IPv4 for broader compatibility in mDNS
                        .find(|iface: &if_addrs::Interface| !iface.is_loopback() && matches!(iface.addr, if_addrs::IfAddr::V4(_)))
                        .map(|iface| iface.addr.ip())
                })
                .unwrap_or_else(|| bind_addr.ip()) // fallback to wildcard if nothing found
        } else {
            bind_addr.ip()
        };

        // Register service
        let service_info = ServiceInfo::new(
            SIBNA_SERVICE_TYPE,
            &instance_name,
            &host_name,
            ad_ip.to_string(),
            bind_addr.port(),
            Some(properties),
        ).map_err(|e| P2pError::InvalidMessage(format!("mDNS service info: {}", e)))?;

        daemon.register(service_info)
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("mDNS register: {}", e))))?;

        debug!("mDNS advertiser started: {} -> {}", instance_name, bind_addr);

        Ok(Self {
            daemon,
            service_type: SIBNA_SERVICE_TYPE.to_string(),
            instance_name,
        })
    }

    /// Browse for local peers.
    ///
    /// Returns a `mpsc::Receiver` channel yielding `DiscoveredPeer` events
    /// as peers pop online or disappear. For this simple MVP, we just yield
    /// a continuous stream of fully resolved peer addresses.
    pub fn browse_peers(&self) -> P2pResult<mpsc::Receiver<DiscoveredPeer>> {
        let receiver = self.daemon.browse(&self.service_type)
            .map_err(|e| P2pError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("mDNS browse: {}", e))))?;

        // Expose a tokio stream to the user to abstract away mdns-sd threads
        let (tx, rx) = mpsc::channel(100);

        let myself = self.instance_name.clone();

        tokio::task::spawn_blocking(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        // Ignore our own broadcast
                        if info.get_fullname().starts_with(&myself) {
                            continue;
                        }

                        // Extract peer ID
                        let props = info.get_properties();
                        let peer_id_hex = match props.get_property_val_str("peer_id") {
                            Some(val) => val.to_string(),
                            None => continue,
                        };

                        // Extract IP
                        let ip = match info.get_addresses().iter().next() {
                            Some(ip) => *ip,
                            None => continue,
                        };
                        let addr = SocketAddr::new(ip, info.get_port());

                        let peer = DiscoveredPeer {
                            peer_id_hex,
                            addr,
                            name: info.get_fullname().to_string(),
                        };

                        if tx.blocking_send(peer).is_err() {
                            break; // channel closed
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, _name) => {
                        // Could yield PeerRemoved events here for tracking
                    }
                    _ => {}
                }
            }
        });

        Ok(rx)
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        if let Err(e) = self.daemon.unregister(&self.service_type) {
            warn!("Failed to unregister mDNS service: {}", e);
        }
    }
}
