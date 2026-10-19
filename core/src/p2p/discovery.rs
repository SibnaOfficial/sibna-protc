//! Local Peer Discovery via Multicast DNS (mDNS)
//!
//! Exposes a `MdnsDiscovery` handle that registers the local node with `mdns-sd`
//! so that nearby devices can find it automatically. It also browses the local
//! network for other peers broadcasting the exact same service type.
//!
//! ## Privacy (SIBNA-2026-029)
//!
//! The mDNS service does **not** broadcast the node's long-term identity key.
//! Instead it advertises a random 16-byte *session token* that is regenerated on
//! every restart.  This prevents cross-session tracking by passive LAN observers.
//! The real peer identity is only exchanged during the encrypted X3DH handshake.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::{P2pError, P2pResult};

const SIBNA_SERVICE_TYPE: &str = "_sibna._tcp.local.";

/// Length of the random session token in bytes (16 = 128 bits).
const SESSION_TOKEN_LEN: usize = 16;

/// A discovered peer from the local network.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Random per-session token identifying the peer on the local network.
    /// This is **not** the long-term identity key — it changes every restart.
    /// Used for deduplication during mDNS discovery only.
    pub session_token: String,
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
    /// - `node_name`: An optional human-readable name, e.g. "Alice's Phone".
    ///
    /// A random session token is generated for this mDNS session.  The caller's
    /// long-term peer ID is **not** used — it is never broadcast over mDNS.
    pub async fn new(bind_addr: SocketAddr, node_name: Option<&str>) -> P2pResult<Self> {
        let daemon = tokio::task::spawn_blocking(ServiceDaemon::new)
            .await
            .map_err(|e| {
                P2pError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("mDNS init task: {}", e),
                ))
            })?
            .map_err(|e| {
                P2pError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("mDNS init: {}", e),
                ))
            })?;

        // Generate a random session token (not the real peer ID).
        let mut token_bytes = [0u8; SESSION_TOKEN_LEN];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let session_hex = hex::encode(token_bytes);

        let instance_name = if let Some(n) = node_name {
            format!("{}-{}", n, &session_hex[..12])
        } else {
            format!("Sibna-{}", &session_hex[..12])
        };

        let mut properties = HashMap::new();
        properties.insert("session".to_string(), session_hex);
        properties.insert("version".to_string(), "2".to_string());

        let host_name = format!("{}.local.", instance_name);

        // If bind_addr is wildcard, we must resolve it to a real IP for mDNS advertisement
        let ad_ip = if bind_addr.ip().is_unspecified() {
            if_addrs::get_if_addrs()
                .ok()
                .and_then(|ifs: Vec<if_addrs::Interface>| {
                    ifs.into_iter()
                        .find(|iface: &if_addrs::Interface| {
                            !iface.is_loopback() && matches!(iface.addr, if_addrs::IfAddr::V4(_))
                        })
                        .map(|iface| iface.addr.ip())
                })
                .unwrap_or_else(|| bind_addr.ip())
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
        )
        .map_err(|e| P2pError::InvalidMessage(format!("mDNS service info: {}", e)))?;

        daemon.register(service_info).map_err(|e| {
            P2pError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mDNS register: {}", e),
            ))
        })?;

        debug!(
            "mDNS advertiser started: {} -> {}",
            instance_name, bind_addr
        );

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
        let receiver = self.daemon.browse(&self.service_type).map_err(|e| {
            P2pError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mDNS browse: {}", e),
            ))
        })?;

        // Expose a tokio stream to the user to abstract away mdns-sd threads
        let (tx, rx) = mpsc::channel::<DiscoveredPeer>(100);

        let myself = self.instance_name.clone();

        tokio::task::spawn_blocking(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        // Ignore our own broadcast
                        if info.get_fullname().starts_with(&myself) {
                            continue;
                        }

                        // Extract session token (the random per-session identifier)
                        let props = info.get_properties();
                        let session_token = match props.get_property_val_str("session") {
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
                            session_token,
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
