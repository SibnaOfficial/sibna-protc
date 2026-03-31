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

/// Compress a message payload using LZ4 for low-bandwidth links
/// Suitable for: LoRa, satellite uplinks, 2G, underwater acoustic modems
pub fn compress(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress an LZ4-compressed payload
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, DecompressError> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|_| DecompressError::InvalidData)
}

/// Decompression error
#[derive(Debug)]
pub enum DecompressError {
    InvalidData,
}

// ─── MQTT Topic Routing ────────────────────────────────────────────────────

/// Sibna MQTT topic format for IoT deployments:
///
/// Publish:    `sibna/msg/{recipient_id_hex}`
/// Subscribe:  `sibna/inbox/{my_id_hex}`
/// PreKey:     `sibna/prekey/{user_id_hex}`
/// Auth:       `sibna/auth/challenge`, `sibna/auth/prove`

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
    out.push(0x01);                 // format version
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
    if data.len() < 6 { return Err(FrameError::TooShort); }
    if data[0] != 0x02 { return Err(FrameError::NoSTX); }
    if data[data.len() - 1] != 0x03 { return Err(FrameError::NoETX); }

    let len = ((data[1] as usize) << 8) | data[2] as usize;
    if data.len() < 3 + len + 3 { return Err(FrameError::IncompleteFrame); }

    let payload = &data[3..3 + len];
    let received_crc = ((data[3 + len] as u16) << 8) | data[3 + len + 1] as u16;
    let expected_crc = crc16(payload);

    if received_crc != expected_crc {
        return Err(FrameError::CrcMismatch { expected: expected_crc, received: received_crc });
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
}
