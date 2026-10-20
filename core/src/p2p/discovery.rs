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

use flume::RecvTimeoutError;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::{P2pError, P2pResult};

const SIBNA_SERVICE_TYPE: &str = "_sibna._tcp.local.";

/// Length of the random session token in bytes (16 = 128 bits).
const SESSION_TOKEN_LEN: usize = 16;

/// How long the browse worker waits for an mDNS event before checking for shutdown.
const BROWSE_POLL_INTERVAL_SECS: u64 = 1;

/// Max retries for `stop_browse()` when the daemon command queue is full (`Error::Again`).
const STOP_BROWSE_MAX_RETRIES: u32 = 3;

/// Stop an mDNS browse operation, retrying on `Error::Again` (queue full).
///
/// The mdns-sd documentation states: "When an error is returned, the caller should
/// retry only when the error is `Error::Again`, otherwise should log and move on."
/// Returns `true` if the browse was stopped successfully, `false` otherwise.
fn stop_browse_with_retry(daemon: &ServiceDaemon, service_type: &str) -> bool {
    let mut retries = 0;
    loop {
        match daemon.stop_browse(service_type) {
            Ok(()) => return true,
            Err(mdns_sd::Error::Again) if retries < STOP_BROWSE_MAX_RETRIES => {
                retries += 1;
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                warn!("Failed to stop mDNS browse: {}", e);
                return false;
            }
        }
    }
}

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
    /// Full service instance name used for `unregister()` (e.g. "AliceDevice-XXXX._sibna._tcp.local.").
    full_service_name: String,
    /// Number of active browse operations. Used to coordinate `stop_browse()`
    /// across concurrent `browse_peers()` calls so that one exiting worker does
    /// not stop a browse that another worker is still using.
    browse_count: Arc<AtomicUsize>,
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

        // Full service instance name for mDNS unregistration.
        let full_service_name = format!("{}.{}", instance_name, SIBNA_SERVICE_TYPE);

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
            full_service_name,
            browse_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Browse for local peers.
    ///
    /// Returns a `mpsc::Receiver` channel yielding `DiscoveredPeer` events
    /// as peers pop online or disappear. For this simple MVP, we just yield
    /// a continuous stream of fully resolved peer addresses.
    ///
    /// The background browse worker uses bounded waits (`recv_timeout`) so it
    /// can detect when the returned receiver is dropped (`tx.is_closed()`) and
    /// stop the mDNS browse operation via `ServiceDaemon::stop_browse()`.
    /// Dropping the `MdnsDiscovery` itself also stops browsing and unregisters.
    ///
    /// Multiple concurrent `browse_peers()` calls are supported: an internal
    /// reference counter ensures `stop_browse()` is only invoked when the last
    /// active browse worker exits, preventing one worker from stopping another's
    /// browse.
    pub fn browse_peers(&self) -> P2pResult<mpsc::Receiver<DiscoveredPeer>> {
        let receiver = self.daemon.browse(&self.service_type).map_err(|e| {
            P2pError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mDNS browse: {}", e),
            ))
        })?;

        // Increment the active browse counter before spawning the worker.
        self.browse_count.fetch_add(1, Ordering::SeqCst);

        // Expose a tokio stream to the user to abstract away mdns-sd threads
        let (tx, rx) = mpsc::channel(100);

        let myself = self.instance_name_for_logging();
        let daemon = self.daemon.clone();
        let service_type = self.service_type.clone();
        let browse_count = self.browse_count.clone();

        tokio::task::spawn_blocking(move || {
            let mut stopped = false;
            loop {
                match receiver.recv_timeout(Duration::from_secs(BROWSE_POLL_INTERVAL_SECS)) {
                    Ok(event) => {
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
                    Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        if tx.is_closed() {
                            break;
                        }
                    }
                }
            }
            // Decrement the active browse counter. Only the last exiting worker
            // calls stop_browse(), preventing it from stopping another worker's
            // still-active browse.
            let remaining = browse_count.fetch_sub(1, Ordering::SeqCst) - 1;
            if remaining == 0 {
                stop_browse_with_retry(&daemon, &service_type);
                stopped = true;
            }
            if !stopped {
                debug!(
                    "mDNS browse worker exited; {} browse(s) still active",
                    remaining
                );
            }
        });

        Ok(rx)
    }

    /// Returns the instance name prefix used to filter out our own broadcasts.
    /// Kept private; used only by the browse worker.
    fn instance_name_for_logging(&self) -> String {
        // Derive from full_service_name by stripping the service type suffix.
        // full_service_name = "instance_name._sibna._tcp.local."
        self.full_service_name
            .strip_suffix(&format!(".{}", SIBNA_SERVICE_TYPE))
            .unwrap_or(&self.full_service_name)
            .to_string()
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        // Stop browsing if any workers are still active.
        let remaining = self.browse_count.load(Ordering::SeqCst);
        if remaining > 0 {
            stop_browse_with_retry(&self.daemon, &self.service_type);
            debug!(
                "mDNS discovery dropped with {} browse worker(s) still active; browse stopped",
                remaining
            );
        }

        // Unregister the service using the full instance name.  Fire-and-forget:
        // we send the command and do not block waiting for the daemon's response.
        // Waiting in a synchronous `Drop` could stall the calling executor thread.
        if let Err(e) = self.daemon.unregister(&self.full_service_name) {
            warn!(
                "Failed to send mDNS unregister command for {}: {}",
                self.full_service_name, e
            );
        }
    }
}
