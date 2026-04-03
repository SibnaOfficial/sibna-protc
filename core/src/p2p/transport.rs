//! TCP Transport — length-prefixed message framing + SOCKS5 proxy support
//!
//! Uses `tokio-util`'s `LengthDelimitedCodec` to split the raw TCP byte
//! stream into discrete messages. Each message is prefixed with a
//! big-endian 4-byte length field (max frame = `max_message_size`).
//!
//! # Anonymity via Tor
//!
//! When `P2pConfig::proxy` is set to a SOCKS5 address (e.g. `"127.0.0.1:9050"` for Tor),
//! all **outgoing** connections are tunneled through the proxy:
//!
//! ```text
//! App ──TCP──► SOCKS5 Proxy (Tor) ──TCP──► Destination
//!              (e.g. 127.0.0.1:9050)
//! ```
//!
//! This hides the real destination IP from network observers.
//! To use with Tor: install the Tor daemon and set `proxy = Some("127.0.0.1:9050".to_string())`.
//!
//! **Note**: Incoming connections are not anonymized here — for full anonymity on the
//! server side, expose your listener via a Tor Hidden Service (.onion address).

use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// Dial `addr` directly (no proxy) and return a framed stream.
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

/// Dial `target_host:target_port` via a SOCKS5 proxy (e.g. Tor at `127.0.0.1:9050`).
///
/// Implements RFC 1928 SOCKS5 with no-authentication method only.
/// The proxy performs DNS resolution so the target hostname is never
/// revealed to a local network observer.
///
/// # Errors
/// - `P2pError::Io` on TCP or SOCKS5 protocol errors
/// - `P2pError::Handshake` if the proxy rejects the connection
pub async fn connect_via_socks5(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    max_message_size: usize,
) -> crate::p2p::P2pResult<FramedStream> {
    // 1. Connect to SOCKS5 proxy
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(crate::p2p::P2pError::Io)?;
    stream.set_nodelay(true).ok();

    // 2. SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth)
    stream.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(crate::p2p::P2pError::Io)?;

    // 3. Read server method selection: VER=5, METHOD
    let mut greeting_reply = [0u8; 2];
    stream.read_exact(&mut greeting_reply)
        .await
        .map_err(crate::p2p::P2pError::Io)?;

    if greeting_reply[0] != 0x05 {
        return Err(crate::p2p::P2pError::Handshake(
            "SOCKS5: unexpected protocol version from proxy".to_string()
        ));
    }
    if greeting_reply[1] == 0xFF {
        return Err(crate::p2p::P2pError::Handshake(
            "SOCKS5: proxy rejected all authentication methods".to_string()
        ));
    }

    // 4. SOCKS5 CONNECT request
    //    VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAIN(3), ADDR, PORT
    let host_bytes = target_host.as_bytes();
    let host_len = host_bytes.len();
    if host_len > 255 {
        return Err(crate::p2p::P2pError::Handshake(
            "SOCKS5: hostname too long (max 255 bytes)".to_string()
        ));
    }

    let mut request = Vec::with_capacity(7 + host_len);
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]); // VER CMD RSV ATYP
    request.push(host_len as u8);                           // domain length
    request.extend_from_slice(host_bytes);                  // domain
    request.push((target_port >> 8) as u8);                 // port MSB
    request.push((target_port & 0xFF) as u8);               // port LSB

    stream.write_all(&request)
        .await
        .map_err(crate::p2p::P2pError::Io)?;

    // 5. Read CONNECT reply header (10 bytes for IPv4, more for domain)
    let mut reply_header = [0u8; 4];
    stream.read_exact(&mut reply_header)
        .await
        .map_err(crate::p2p::P2pError::Io)?;

    if reply_header[0] != 0x05 {
        return Err(crate::p2p::P2pError::Handshake(
            "SOCKS5: unexpected version in CONNECT reply".to_string()
        ));
    }
    if reply_header[1] != 0x00 {
        let reason = socks5_error_message(reply_header[1]);
        return Err(crate::p2p::P2pError::Handshake(
            format!("SOCKS5: proxy refused connection — {}", reason)
        ));
    }

    // 6. Consume the BND.ADDR and BND.PORT fields (we don't use them)
    let atyp = reply_header[3];
    let _bound_addr: Vec<u8> = match atyp {
        0x01 => {  // IPv4
            let mut buf = [0u8; 6]; // 4 addr + 2 port
            stream.read_exact(&mut buf).await.map_err(crate::p2p::P2pError::Io)?;
            buf.to_vec()
        }
        0x04 => {  // IPv6
            let mut buf = [0u8; 18]; // 16 addr + 2 port
            stream.read_exact(&mut buf).await.map_err(crate::p2p::P2pError::Io)?;
            buf.to_vec()
        }
        0x03 => {  // Domain name
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await.map_err(crate::p2p::P2pError::Io)?;
            let mut buf = vec![0u8; len_buf[0] as usize + 2]; // name + 2 port bytes
            stream.read_exact(&mut buf).await.map_err(crate::p2p::P2pError::Io)?;
            buf
        }
        _ => {
            return Err(crate::p2p::P2pError::Handshake(
                format!("SOCKS5: unknown address type 0x{:02X} in reply", atyp)
            ));
        }
    };

    // 7. Tunnel is established — wrap in framing codec
    Ok(wrap_stream(stream, max_message_size))
}

/// Intelligible error string for SOCKS5 reply codes.
fn socks5_error_message(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _    => "unknown error",
    }
}

/// Connect to `addr` using the optional SOCKS5 proxy.
///
/// - If `proxy` is `Some(proxy_addr)`, routes through SOCKS5.
/// - If `require_anonymity` is true and `proxy` is `None`, this will cleanly return an Error.
/// - If `proxy` is `None`, connects directly.
///
/// `addr` must be in `"host:port"` format.
pub async fn connect_with_optional_proxy(
    addr: &str,
    proxy: Option<&str>,
    require_anonymity: bool,
    max_message_size: usize,
) -> crate::p2p::P2pResult<FramedStream> {
    if let Some(proxy_addr) = proxy {
        // Parse host:port from target address
        let (host, port) = parse_host_port(addr)?;
        connect_via_socks5(proxy_addr, &host, port, max_message_size).await
    } else {
        if require_anonymity {
            return Err(crate::p2p::P2pError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Anonymity is required but no SOCKS5 proxy was provided. Direct TCP connection blocked to prevent IP leak.",
            )));
        }
        connect(addr, max_message_size).await
    }
}

/// Parse a `"host:port"` string into `(host, port)`.
fn parse_host_port(addr: &str) -> crate::p2p::P2pResult<(String, u16)> {
    // Handle IPv6 like [::1]:8080
    if let Some(bracket_end) = addr.find(']') {
        let host = addr[1..bracket_end].to_string();
        let rest = &addr[bracket_end + 1..];
        let port_str = rest.strip_prefix(':').unwrap_or("");
        let port = port_str.parse::<u16>().map_err(|_| {
            crate::p2p::P2pError::Handshake(format!("invalid port in address: {addr}"))
        })?;
        return Ok((host, port));
    }

    // Plain host:port
    let mut parts = addr.rsplitn(2, ':');
    let port_str = parts.next().ok_or_else(|| {
        crate::p2p::P2pError::Handshake(format!("invalid address format: {addr}"))
    })?;
    let host = parts.next().ok_or_else(|| {
        crate::p2p::P2pError::Handshake(format!("missing host in address: {addr}"))
    })?;
    let port = port_str.parse::<u16>().map_err(|_| {
        crate::p2p::P2pError::Handshake(format!("invalid port in address: {addr}"))
    })?;
    Ok((host.to_string(), port))
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
