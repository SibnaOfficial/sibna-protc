/*
 * sibna.h — Universal C FFI Header for Sibna Protocol
 *
 * Compatible with:
 *   - Any C/C++ system (Linux, Windows, macOS, FreeRTOS, Zephyr, bare-metal)
 *   - Embedded MCUs (ARM Cortex-M, RISC-V, ESP32, STM32, Arduino-compatible)
 *   - Drones (PX4, ArduPilot companion computers)
 *   - Submarines / ROVs (serial/UART interfaces)
 *   - Robots (ROS2 nodes, SLAM systems)
 *   - IoT gateways (MQTT bridges)
 *   - Ships / Maritime (NMEA-compatible serial protocols)
 *
 * Build the Rust core as a C-compatible shared/static library:
 *   cargo build --release --features ffi
 *   # outputs: target/release/libsibna_core.so (Linux)
 *   #          target/release/sibna_core.dll   (Windows)
 *   #          target/release/libsibna_core.a  (static, for embedded)
 *
 * Usage:
 *   #include "sibna.h"
 *   // Link with -lsibna_core
 */

#ifndef SIBNA_H
#define SIBNA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Result Codes ──────────────────────────────────────────────────────────── */
#define SIBNA_OK                     0
#define SIBNA_ERR_INVALID_KEY        1
#define SIBNA_ERR_INVALID_SIGNATURE  2
#define SIBNA_ERR_SESSION_NOT_FOUND  3
#define SIBNA_ERR_RATE_LIMITED       4
#define SIBNA_ERR_EXPIRED            5
#define SIBNA_ERR_REPLAY             6
#define SIBNA_ERR_BUFFER_TOO_SMALL   7
#define SIBNA_ERR_UNKNOWN            99

/* ── Key sizes ─────────────────────────────────────────────────────────────── */
#define SIBNA_IDENTITY_KEY_LEN    32
#define SIBNA_SIGNATURE_LEN       64
#define SIBNA_BUNDLE_ID_LEN       16
#define SIBNA_SHARED_SECRET_LEN   32
#define SIBNA_MESSAGE_KEY_LEN     32

/* ── Opaque context handle ─────────────────────────────────────────────────── */
typedef struct SibnaContext SibnaContext;

/* ── Context Lifecycle ─────────────────────────────────────────────────────── */

/**
 * sibna_context_new — Create a new Sibna secure context
 *
 * @param password      Master password bytes (UTF-8), or NULL to generate random key
 * @param password_len  Length of password, or 0 if password is NULL
 * @return  Opaque handle, or NULL on failure
 *
 * Security: Context owns all cryptographic material. Zeroizes on sibna_context_free().
 */
SibnaContext* sibna_context_new(const uint8_t* password, size_t password_len);

/**
 * sibna_context_free — Destroy context and zeroize all cryptographic material
 *
 * Always call this before program exit. Automatically zeroizes:
 *   - Identity keys, signed prekeys, one-time prekeys
 *   - All session ratchet states
 *   - Storage encryption key
 */
void sibna_context_free(SibnaContext* ctx);

/* ── Identity ──────────────────────────────────────────────────────────────── */

/**
 * sibna_generate_identity — Generate a new Ed25519 + X25519 identity keypair
 *
 * @param ctx         Context handle
 * @param out_pub_key Output buffer for 32-byte Ed25519 public key
 * @return  SIBNA_OK on success
 */
int32_t sibna_generate_identity(SibnaContext* ctx, uint8_t out_pub_key[32]);

/**
 * sibna_get_identity_key — Get the current identity public key
 *
 * @param ctx         Context handle
 * @param out_pub_key Output buffer for 32-byte public key
 * @return  SIBNA_OK on success, SIBNA_ERR_INVALID_KEY if no identity exists
 */
int32_t sibna_get_identity_key(SibnaContext* ctx, uint8_t out_pub_key[32]);

/* ── PreKey Bundle ─────────────────────────────────────────────────────────── */

/**
 * sibna_generate_prekey_bundle — Generate and sign a PreKeyBundle for upload to server
 *
 * The bundle is Ed25519-signed over the full payload. Upload to:
 *   POST /v1/prekeys/upload  { "bundle_hex": "<hex>" }
 *
 * @param ctx         Context handle
 * @param out_buf     Output buffer for serialized bundle bytes
 * @param out_len     IN: buffer capacity (must be >= 256 bytes), OUT: actual bytes written
 * @return  SIBNA_OK or error code
 */
int32_t sibna_generate_prekey_bundle(
    SibnaContext* ctx,
    uint8_t* out_buf,
    size_t* out_len
);

/* ── Session — X3DH Handshake ──────────────────────────────────────────────── */

/**
 * sibna_perform_handshake — Initiate or complete X3DH with a peer
 *
 * Call this after fetching the peer's PreKeyBundle from the server.
 *
 * @param ctx                Context handle
 * @param peer_id            Peer identity key (32 bytes)
 * @param peer_signed_prekey Peer signed prekey (32 bytes)
 * @param peer_onetime_prekey Peer one-time prekey (32 bytes), or NULL
 * @param initiator          1 = initiator (sender), 0 = responder (receiver)
 * @return  SIBNA_OK or error code
 */
int32_t sibna_perform_handshake(
    SibnaContext* ctx,
    const uint8_t peer_id[32],
    const uint8_t peer_signed_prekey[32],
    const uint8_t* peer_onetime_prekey,   /* nullable */
    int32_t initiator
);

/* ── Session — Message Encryption ─────────────────────────────────────────── */

/**
 * sibna_encrypt — Encrypt a message using the Double Ratchet session
 *
 * @param ctx          Context handle
 * @param session_id   Peer's identity key (32 bytes, used as session key)
 * @param plaintext    Message bytes
 * @param plaintext_len Length of plaintext
 * @param out_buf      Output buffer for ciphertext
 * @param out_len      IN: capacity, OUT: actual ciphertext length
 * @return  SIBNA_OK or error code
 */
int32_t sibna_encrypt(
    SibnaContext* ctx,
    const uint8_t session_id[32],
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* out_buf,
    size_t* out_len
);

/**
 * sibna_decrypt — Decrypt a message using the Double Ratchet session
 *
 * @param ctx           Context handle
 * @param session_id    Peer's identity key (32 bytes)
 * @param ciphertext    Encrypted message
 * @param ciphertext_len Length of ciphertext
 * @param out_buf       Output buffer for plaintext
 * @param out_len       IN: capacity, OUT: actual plaintext length
 * @return  SIBNA_OK or error code
 */
int32_t sibna_decrypt(
    SibnaContext* ctx,
    const uint8_t session_id[32],
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* out_buf,
    size_t* out_len
);

/* ── Group Messaging ───────────────────────────────────────────────────────── */

/**
 * sibna_group_create — Create a new group session
 *
 * @param ctx       Context handle
 * @param group_id  32-byte group identifier
 * @return  SIBNA_OK or error code
 */
int32_t sibna_group_create(SibnaContext* ctx, const uint8_t group_id[32]);

/**
 * sibna_group_add_member — Add a member's public key to a group
 *
 * @param ctx        Context handle
 * @param group_id   32-byte group identifier
 * @param member_key Member's identity public key (32 bytes)
 * @return  SIBNA_OK or error code
 */
int32_t sibna_group_add_member(
    SibnaContext* ctx,
    const uint8_t group_id[32],
    const uint8_t member_key[32]
);

/* ── Safety Numbers ────────────────────────────────────────────────────────── */

/**
 * sibna_safety_number — Generate a safety number for out-of-band verification
 *
 * The safety number uniquely identifies the key relationship between two parties.
 * Users compare this over a trusted channel (voice call, in-person, QR code)
 * to verify no MITM took place.
 *
 * @param local_key   Local identity public key (32 bytes)
 * @param remote_key  Remote identity public key (32 bytes)
 * @param out_number  Output buffer for 60-character safety number string (null-terminated)
 * @return  SIBNA_OK or error code
 */
int32_t sibna_safety_number(
    const uint8_t local_key[32],
    const uint8_t remote_key[32],
    char out_number[61]
);

/* ── IoT Utilities ─────────────────────────────────────────────────────────── */

/**
 * sibna_frame_serial — Wrap a payload in a serial frame (STX+LEN+CRC+ETX)
 *
 * Use for UART / RS-485 / CAN bus transmission.
 *
 * @param payload      Raw payload bytes
 * @param payload_len  Length of payload
 * @param out_frame    Output buffer for framed bytes
 * @param out_len      IN: capacity, OUT: frame length
 * @return  SIBNA_OK or SIBNA_ERR_BUFFER_TOO_SMALL
 */
int32_t sibna_frame_serial(
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out_frame,
    size_t* out_len
);

/**
 * sibna_parse_serial_frame — Parse a serial frame, verify CRC
 *
 * @param frame       Raw frame bytes
 * @param frame_len   Length of frame
 * @param out_payload Output buffer for inner payload
 * @param out_len     IN: capacity, OUT: payload length
 * @return  SIBNA_OK or SIBNA_ERR_INVALID_SIGNATURE (CRC mismatch)
 */
int32_t sibna_parse_serial_frame(
    const uint8_t* frame,
    size_t frame_len,
    uint8_t* out_payload,
    size_t* out_len
);

/* ── Anti-Forensics ────────────────────────────────────────────────────────── */

/**
 * sibna_secure_wipe — Securely overwrite a buffer with zeros
 *
 * Uses volatile writes to prevent compiler optimization from removing the wipe.
 * Call this on any sensitive data before freeing or reusing the buffer.
 *
 * @param buf  Buffer to wipe
 * @param len  Length of buffer
 */
void sibna_secure_wipe(uint8_t* buf, size_t len);

/* ── Version ───────────────────────────────────────────────────────────────── */

/**
 * sibna_version — Get the protocol version string
 *
 * @return  Null-terminated UTF-8 version string (e.g., "11.0.0")
 */
const char* sibna_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIBNA_H */
