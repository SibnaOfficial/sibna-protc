//! Connected peer handle
//!
//! A `Peer` wraps a `FramedStream` and a `DoubleRatchetSession`.
//! All application-level send/receive calls go through this struct.
//!
//! `tokio::sync::Mutex` is used (not `parking_lot::Mutex`) because the guard
//! must be held across `.await` points where `SinkExt`/`StreamExt` are called.

use tokio::sync::Mutex;
use futures::{SinkExt, StreamExt};

use crate::ratchet::DoubleRatchetSession;
use super::{P2pError, P2pResult, transport::FramedStream};

/// A fully authenticated, encrypted connection to a remote peer.
///
/// Obtain a `Peer` from [`crate::p2p::P2pNode::connect`] or
/// [`crate::p2p::P2pNode::accept`]. Use [`send_message`](Peer::send_message)
/// and [`recv_message`](Peer::recv_message) for all data exchange.
pub struct Peer {
    /// Remote peer's Ed25519 identity public key (stable peer identifier)
    peer_id: [u8; 32],
    /// TCP framed stream — wrapped in `tokio::sync::Mutex` so the guard
    /// can be held across `.await` points.
    stream: Mutex<FramedStream>,
    /// Established Double Ratchet session.  `DoubleRatchetSession` uses its
    /// own internal `RwLock`, so `&self` is sufficient for encrypt/decrypt.
    session: DoubleRatchetSession,
    /// Remote socket address
    remote_addr: std::net::SocketAddr,
}

impl Peer {
    /// Create a new `Peer`.  Called internally by `P2pNode`.
    pub(crate) fn new(
        peer_id: [u8; 32],
        stream: FramedStream,
        session: DoubleRatchetSession,
        remote_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            peer_id,
            stream: Mutex::new(stream),
            session,
            remote_addr,
        }
    }

    /// Return the remote peer's Ed25519 identity public key.
    ///
    /// This is the stable identifier for the peer, verifiable via Safety Numbers
    /// or out-of-band confirmation.
    pub fn peer_id(&self) -> &[u8; 32] {
        &self.peer_id
    }

    /// Return the remote peer's identity as a short hex string (first 8 bytes).
    pub fn peer_id_hex(&self) -> String {
        hex::encode(&self.peer_id[..8])
    }

    /// Return the remote socket address.
    pub fn remote_addr(&self) -> std::net::SocketAddr {
        self.remote_addr
    }

    /// Encrypt `plaintext` with the Double Ratchet session and send it to the peer.
    ///
    /// # Errors
    /// - `P2pError::Crypto` — ratchet encryption failed
    /// - `P2pError::Io` — TCP write error
    pub async fn send_message(&self, plaintext: &[u8]) -> P2pResult<()> {
        // Encrypt first (no lock held)
        let ciphertext = self.session
            .encrypt(plaintext, b"p2p-message")
            .map_err(|e| P2pError::Crypto(format!("encrypt: {:?}", e)))?;

        // Then send (lock held only across this single async write)
        let mut stream = self.stream.lock().await;
        stream.send(bytes::Bytes::from(ciphertext))
            .await
            .map_err(|e: std::io::Error| P2pError::Io(e))
    }

    /// Receive and decrypt the next message from the peer.
    ///
    /// Blocks until a message arrives or the peer disconnects.
    ///
    /// # Errors
    /// - `P2pError::Disconnected` — peer closed the connection
    /// - `P2pError::Framing` — codec error assembling the frame
    /// - `P2pError::Crypto` — ratchet decryption failed (includes replay detection)
    pub async fn recv_message(&self) -> P2pResult<Vec<u8>> {
        let ciphertext = {
            let mut stream = self.stream.lock().await;
            stream.next().await
                .ok_or(P2pError::Disconnected)?
                .map_err(|e: std::io::Error| P2pError::Framing(e.to_string()))?
        };

        self.session
            .decrypt(&ciphertext, b"p2p-message")
            .map_err(|e| P2pError::Crypto(format!("decrypt: {:?}", e)))
    }
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("peer_id_hex", &self.peer_id_hex())
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}
