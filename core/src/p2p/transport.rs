//! TCP Transport — length-prefixed message framing
//!
//! Uses `tokio-util`'s `LengthDelimitedCodec` to split the raw TCP byte
//! stream into discrete messages. Each message is prefixed with a
//! big-endian 4-byte length field (max frame = `max_message_size`).

use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// A length-delimited framed TCP stream carrying `Bytes` messages.
/// All reads and writes are length-prefixed; the codec handles assembly.
pub type FramedStream = Framed<TcpStream, LengthDelimitedCodec>;

/// Maximum frame size: 10 MB (matches `sibna_core::Config::max_message_size`).
pub const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// Wrap a raw `TcpStream` in a length-delimited framing codec.
pub fn wrap_stream(stream: TcpStream, max_message_size: usize) -> FramedStream {
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(max_message_size)
        .new_codec();
    Framed::new(stream, codec)
}

/// Dial `addr` and return a framed stream.
///
/// # Errors
/// Returns `P2pError::Io` on connection failure.
pub async fn connect(
    addr: &str,
    max_message_size: usize,
) -> crate::p2p::P2pResult<FramedStream> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(crate::p2p::P2pError::Io)?;
    // Disable Nagle's algorithm for lower latency on small messages
    stream.set_nodelay(true).ok();
    Ok(wrap_stream(stream, max_message_size))
}

/// Bind a TCP listener and return it.
///
/// # Errors
/// Returns `P2pError::Io` on bind failure.
pub async fn listen(
    addr: std::net::SocketAddr,
) -> crate::p2p::P2pResult<TcpListener> {
    TcpListener::bind(addr)
        .await
        .map_err(crate::p2p::P2pError::Io)
}

/// Accept one connection from a `TcpListener` and return a framed stream.
///
/// # Errors
/// Returns `P2pError::Io` on accept failure, `P2pError::Disconnected` if
/// the listener is closed.
pub async fn accept(
    listener: &TcpListener,
    max_message_size: usize,
) -> crate::p2p::P2pResult<(FramedStream, std::net::SocketAddr)> {
    let (stream, addr) = listener
        .accept()
        .await
        .map_err(crate::p2p::P2pError::Io)?;
    stream.set_nodelay(true).ok();
    Ok((wrap_stream(stream, max_message_size), addr))
}
