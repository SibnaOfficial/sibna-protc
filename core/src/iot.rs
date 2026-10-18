#![allow(missing_docs)]
//! IoT / Constrained Device Adapter
//!
//! This module provides utilities for deploying Sibna Protocol on:
//! - Microcontrollers (ARM Cortex-M, RISC-V)
//! - IoT sensor nodes (MQTT-based)
//! - Drones, submarines, robots (serial / UDP transport)
//!
//! ## Design Principles
//! - Zero dynamic allocation where possible
//! - LZ4 compression for low-bandwidth links
//! - Hardware entropy source abstraction
//! - MQTT topic-based routing

/// Hardware entropy source trait
/// Implement this for your MCU's RNG peripheral (TRNG, HRNG, etc.)
pub trait HardwareRng: Send + Sync {
    /// Fill `buf` with cryptographically random bytes from hardware source
    /// Must return Err if entropy source fails (thermal noise failure, etc.)
    fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), RngError>;
}

/// Error from hardware RNG
#[derive(Debug)]
pub enum RngError {
    /// Hardware RNG not available or failed self-test
    HardwareFailure,
    /// Entropy pool not yet seeded
    NotReady,
}

/// POSIX/stdlib software fallback (for Linux-based IoT: Raspberry Pi, BeagleBone, etc.)
pub struct SoftwareRng;

impl HardwareRng for SoftwareRng {
    fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), RngError> {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buf);
        Ok(())
    }
}

// ─── LZ4 Compression (low-bandwidth mode) ─────────────────────────────────

/// Maximum decompressed output size enforced by `decompress` (20 MB).
pub(crate) const MAX_DECOMPRESSED_SIZE: usize = 20 * 1024 * 1024;

/// Compress a message payload using LZ4 for low-bandwidth links
/// Suitable for: LoRa, satellite uplinks, 2G, underwater acoustic modems
pub fn compress(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress an LZ4-compressed payload.
///
/// The LZ4 `decompress_size_prepended` frame always begins with a 4-byte
/// little-endian declared uncompressed size. That size is used to size the
/// output buffer, so it MUST be validated before any allocation or
/// decompression. The previous implementation only checked the declared size
/// when `data.len() > 4`, which let a 4-byte input skip the guard entirely and
/// force an allocation sized by an attacker-controlled 4-byte length (a
/// classic decompression-bomb / allocation DoS).
///
/// The declared size is enforced for every input that carries a full 4-byte
/// header, and `lz4_flex::decompress_size_prepended` never writes more than
/// the declared size into its buffer, so the actual output is bounded by the
/// capped declared size. No unbounded allocation can occur.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, DecompressError> {
    // A valid LZ4 size-prepended stream always carries at least the 4-byte
    // declared-size header. Reject anything shorter up front.
    if data.len() < 4 {
        return Err(DecompressError::InvalidData);
    }

    let declared_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

    // Enforce the advertised-size limit BEFORE any allocation/decompression.
    if declared_size > MAX_DECOMPRESSED_SIZE {
        return Err(DecompressError::TooLarge);
    }

    // The decompressor allocates a buffer sized to the (capped) declared size
    // and never writes more than that, so actual output cannot exceed the
    // enforced limit regardless of the compressed stream contents.
    lz4_flex::decompress_size_prepended(data).map_err(|_| DecompressError::InvalidData)
}

/// Decompression error
#[derive(Debug, PartialEq, Eq)]
pub enum DecompressError {
    InvalidData,
    TooLarge,
}

// ─── MQTT Topic Routing ────────────────────────────────────────────────────

/// Sibna MQTT topic format for IoT deployments:
///
/// Publish:    `sibna/msg/{recipient_id_hex}`
/// Subscribe:  `sibna/inbox/{my_id_hex}`
/// PreKey:     `sibna/prekey/{user_id_hex}`
/// Auth:       `sibna/auth/challenge`, `sibna/auth/prove`
///
/// Generate the MQTT topic for sending to a recipient
pub fn mqtt_send_topic(recipient_id_hex: &str) -> String {
    format!("sibna/msg/{}", recipient_id_hex)
}

/// Generate the MQTT topic this device should subscribe to for incoming messages
pub fn mqtt_inbox_topic(my_id_hex: &str) -> String {
    format!("sibna/inbox/{}", my_id_hex)
}

/// Build a compact MQTT payload (compressed sealed envelope)
///
/// Format (wire): [1 byte flags | 32 bytes recipient_id | N bytes encrypted payload]
/// Flags: bit 0 = LZ4 compressed
pub fn build_mqtt_payload(
    recipient_id: &[u8; 32],
    encrypted_payload: &[u8],
    compress_payload: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + encrypted_payload.len());
    out.push(if compress_payload { 0x01 } else { 0x00 });
    out.extend_from_slice(recipient_id);

    if compress_payload {
        let compressed = compress(encrypted_payload);
        out.extend_from_slice(&compressed);
    } else {
        out.extend_from_slice(encrypted_payload);
    }
    out
}

/// Parse an MQTT payload received from topic `sibna/inbox/{id}`
pub fn parse_mqtt_payload(raw: &[u8]) -> Result<(bool, [u8; 32], Vec<u8>), ParseError> {
    if raw.len() < 33 {
        return Err(ParseError::TooShort);
    }
    let compressed = raw[0] & 0x01 != 0;
    let mut recipient: [u8; 32] = [0u8; 32];
    recipient.copy_from_slice(&raw[1..33]);
    let payload_raw = &raw[33..];
    let payload = if compressed {
        decompress(payload_raw).map_err(|_| ParseError::DecompressionFailed)?
    } else {
        payload_raw.to_vec()
    };
    Ok((compressed, recipient, payload))
}

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort,
    DecompressionFailed,
}

// ─── Constrained Device Session Persistence ───────────────────────────────

/// Serialize a session state to bytes (for writing to flash/EEPROM/SD card)
/// The serialized bytes should be encrypted with the device's storage key
/// before writing to non-volatile storage.
///
/// Usage for embedded systems:
/// ```ignore
/// let state_bytes = session_to_bytes(&session_state)?;
/// let encrypted = aes_ctr_encrypt(&storage_key, &state_bytes);
/// flash_write(SESSION_FLASH_ADDR, &encrypted);
/// ```
pub fn session_to_bytes(state: &[u8]) -> Vec<u8> {
    // Prepend magic + version for validation on restore
    let mut out = Vec::with_capacity(4 + state.len());
    out.extend_from_slice(b"SIBN"); // magic
    out.push(0x01); // format version
    out.extend_from_slice(state);
    out
}

/// Restore session state from bytes (read from flash/EEPROM/SD card)
pub fn session_from_bytes(raw: &[u8]) -> Result<Vec<u8>, SessionRestoreError> {
    if raw.len() < 5 {
        return Err(SessionRestoreError::TooShort);
    }
    if &raw[..4] != b"SIBN" {
        return Err(SessionRestoreError::InvalidMagic);
    }
    if raw[4] != 0x01 {
        return Err(SessionRestoreError::UnsupportedVersion(raw[4]));
    }
    Ok(raw[5..].to_vec())
}

/// Session restore error
#[derive(Debug)]
pub enum SessionRestoreError {
    TooShort,
    InvalidMagic,
    UnsupportedVersion(u8),
}

// ─── Serial/UART Frame Format (for drones, submarines, robots) ────────────

/// Frame a Sibna payload for transmission over serial/UART/CAN bus
///
/// Frame structure:
/// [STX (0x02)] [LEN: 2 bytes big-endian] [PAYLOAD: N bytes] [CRC16: 2 bytes] [ETX (0x03)]
pub fn frame_serial(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let crc = crc16(payload);
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.push(0x02); // STX
    frame.push((len >> 8) as u8);
    frame.push(len as u8);
    frame.extend_from_slice(payload);
    frame.push((crc >> 8) as u8);
    frame.push(crc as u8);
    frame.push(0x03); // ETX
    frame
}

/// Parse a serial frame, return payload if CRC is valid
pub fn parse_serial_frame(data: &[u8]) -> Result<Vec<u8>, FrameError> {
    if data.len() < 6 {
        return Err(FrameError::TooShort);
    }
    if data[0] != 0x02 {
        return Err(FrameError::NoSTX);
    }
    if data[data.len() - 1] != 0x03 {
        return Err(FrameError::NoETX);
    }

    let len = ((data[1] as usize) << 8) | data[2] as usize;
    if data.len() < 3 + len + 3 {
        return Err(FrameError::IncompleteFrame);
    }

    let payload = &data[3..3 + len];
    let received_crc = ((data[3 + len] as u16) << 8) | data[3 + len + 1] as u16;
    let expected_crc = crc16(payload);

    if received_crc != expected_crc {
        return Err(FrameError::CrcMismatch {
            expected: expected_crc,
            received: received_crc,
        });
    }
    Ok(payload.to_vec())
}

/// Frame error
#[derive(Debug)]
pub enum FrameError {
    TooShort,
    NoSTX,
    NoETX,
    IncompleteFrame,
    CrcMismatch { expected: u16, received: u16 },
}

/// CRC-16/IBM (used in MODBUS, widely supported in embedded toolchains)
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for byte in data {
        crc ^= *byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4_roundtrip() {
        let data = b"Hello from underwater drone 001! This is a test encrypted payload.";
        let compressed = compress(data);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data.as_ref(), decompressed.as_slice());
    }

    #[test]
    fn test_serial_frame_roundtrip() {
        let payload = b"SIBNA_SEALED_ENVELOPE_XYZ";
        let frame = frame_serial(payload);
        let recovered = parse_serial_frame(&frame).unwrap();
        assert_eq!(payload.as_ref(), recovered.as_slice());
    }

    #[test]
    fn test_serial_frame_tamper() {
        let payload = b"secret message";
        let mut frame = frame_serial(payload);
        // Flip a byte in the payload — CRC should catch it
        frame[4] ^= 0xFF;
        assert!(parse_serial_frame(&frame).is_err());
    }

    #[test]
    fn test_mqtt_payload_roundtrip() {
        let recipient = [0xABu8; 32];
        let payload = b"encrypted_sealed_data";
        let mqtt_pkt = build_mqtt_payload(&recipient, payload, true);
        let (compressed, rcpt, data) = parse_mqtt_payload(&mqtt_pkt).unwrap();
        assert!(compressed);
        assert_eq!(rcpt, recipient);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_session_persistence_roundtrip() {
        let state = b"ratchet_state_bytes";
        let serialized = session_to_bytes(state);
        let restored = session_from_bytes(&serialized).unwrap();
        assert_eq!(state.as_ref(), restored.as_slice());
    }

    #[test]
    fn test_mqtt_topics() {
        let id = "deadbeef01234567";
        assert_eq!(mqtt_send_topic(id), format!("sibna/msg/{}", id));
        assert_eq!(mqtt_inbox_topic(id), format!("sibna/inbox/{}", id));
    }

    // ── Decompression boundary / adversarial tests (SIBNA-DECOMPRESS) ───────

    #[test]
    fn test_decompress_empty_input_rejected() {
        assert!(decompress(&[]).is_err());
    }

    #[test]
    fn test_decompress_short_header_rejected() {
        // 1, 2, or 3 bytes cannot carry a valid 4-byte declared-size header.
        for len in 0..4 {
            assert!(
                decompress(&vec![0u8; len]).is_err(),
                "len={} should be rejected",
                len
            );
        }
    }

    #[test]
    fn test_decompress_roundtrip_within_limit() {
        let data = b"SIBNA decompression boundary test payload.";
        let compressed = compress(data);
        let out = decompress(&compressed).unwrap();
        assert_eq!(data, out.as_slice());
    }

    #[test]
    fn test_decompress_oversized_declared_size_rejected() {
        // Exactly 4 bytes: header only, declares 0xFFFFFFFF (~4 GiB). The old
        // `data.len() > 4` guard skipped this case entirely.
        let huge: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            decompress(&huge),
            Err(DecompressError::TooLarge),
            "4-byte input declaring ~4 GiB must be rejected before allocation"
        );
    }

    #[test]
    fn test_decompress_declared_size_at_limit_accepted() {
        // Declared size exactly == MAX_DECOMPRESSED_SIZE must be accepted
        // (boundary value). Use a valid minimal stream: declare the limit but
        // the decompressor will error on invalid data -> InvalidData, not
        // TooLarge, proving the cap was applied.
        let at_limit: [u8; 4] = [
            (MAX_DECOMPRESSED_SIZE as u32 & 0xFF) as u8,
            ((MAX_DECOMPRESSED_SIZE as u32) >> 8 & 0xFF) as u8,
            ((MAX_DECOMPRESSED_SIZE as u32) >> 16 & 0xFF) as u8,
            ((MAX_DECOMPRESSED_SIZE as u32) >> 24 & 0xFF) as u8,
        ];
        let result = decompress(&at_limit);
        // The stream is not valid LZ4, so we get InvalidData — but never
        // TooLarge, because the declared size is within the cap.
        assert!(
            matches!(result, Err(DecompressError::InvalidData)),
            "declared size == limit must not be rejected as TooLarge; got {:?}",
            result
        );
    }

    #[test]
    fn test_decompress_declared_size_above_limit_rejected() {
        // Declared size = MAX + 1 must be rejected as TooLarge.
        let over: [u8; 4] = [
            (((MAX_DECOMPRESSED_SIZE + 1) as u32) & 0xFF) as u8,
            ((((MAX_DECOMPRESSED_SIZE + 1) as u32) >> 8) & 0xFF) as u8,
            ((((MAX_DECOMPRESSED_SIZE + 1) as u32) >> 16) & 0xFF) as u8,
            ((((MAX_DECOMPRESSED_SIZE + 1) as u32) >> 24) & 0xFF) as u8,
        ];
        assert_eq!(decompress(&over), Err(DecompressError::TooLarge));
    }

    #[test]
    fn test_decompress_truncated_stream_rejected() {
        // Valid header declaring a modest size, but the stream is truncated
        // before the declared amount of output can be produced.
        let declared: [u8; 4] = [100, 0, 0, 0]; // declare 100 bytes
        let truncated = [declared.as_slice(), &[0x04u8; 2]].concat();
        assert!(decompress(&truncated).is_err());
    }

    #[test]
    fn test_decompress_malformed_stream_rejected() {
        // Header declares a small size, but payload is not valid LZ4.
        let declared: [u8; 4] = [10, 0, 0, 0];
        let garbage = [declared.as_slice(), &[0xFFu8; 16]].concat();
        assert!(decompress(&garbage).is_err());
    }

    #[test]
    fn test_decompress_empty_payload_roundtrip() {
        let data = b"";
        let compressed = compress(data);
        let out = decompress(&compressed).unwrap();
        assert_eq!(data, out.as_slice());
    }

    #[test]
    fn test_parse_mqtt_payload_rejects_bad_compression() {
        let recipient = [0x42u8; 32];
        // Build a payload with the compressed flag set but invalid LZ4 bytes.
        let mut raw = Vec::new();
        raw.push(0x01); // compressed flag
        raw.extend_from_slice(&recipient);
        raw.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]); // garbage
        assert!(parse_mqtt_payload(&raw).is_err());
    }
}
