//! FFI Bindings for Cross-Platform Integration - Hardened Edition
//!
//! Provides C-compatible FFI bindings for integrating with other languages.
//! All functions are designed to be safe and prevent memory corruption.

use std::cell::RefCell;
use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::slice;
use std::ptr;
use zeroize::Zeroize;

use crate::error::ProtocolError;
use crate::crypto::{CryptoHandler, SecureRandom, KEY_LENGTH};
use crate::Config;

/// Opaque handle to a secure context
pub type SibnaContext = c_void;

/// Opaque handle to a session
pub type SibnaSession = c_void;

/// Opaque handle to a group
pub type SibnaGroup = c_void;

/// Result codes for FFI operations
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SibnaResult {
    /// Success
    Ok = 0,
    /// Invalid argument
    InvalidArgument = 1,
    /// Invalid key
    InvalidKey = 2,
    /// Encryption failed
    EncryptionFailed = 3,
    /// Decryption failed
    DecryptionFailed = 4,
    /// Out of memory
    OutOfMemory = 5,
    /// Invalid state
    InvalidState = 6,
    /// Session not found
    SessionNotFound = 7,
    /// Key not found
    KeyNotFound = 8,
    /// Rate limit exceeded
    RateLimitExceeded = 9,
    /// Internal error
    InternalError = 10,
    /// Buffer too small
    BufferTooSmall = 11,
    /// Invalid ciphertext
    InvalidCiphertext = 12,
    /// Authentication failed
    AuthenticationFailed = 13,
}

/// FFI-safe byte buffer
#[repr(C)]
pub struct ByteBuffer {
    /// Pointer to data
    pub data: *mut u8,
    /// Length of data
    pub len: usize,
    /// Capacity of buffer
    pub capacity: usize,
}

impl ByteBuffer {
    /// Create a new byte buffer
    pub fn new(data: Vec<u8>) -> Self {
        let mut data = data;
        let len = data.len();
        let capacity = data.capacity();
        let ptr = data.as_mut_ptr();
        std::mem::forget(data);
        
        Self {
            data: ptr,
            len,
            capacity,
        }
    }

    /// Create an empty buffer
    pub fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }

    /// Convert to Vec<u8> (unsafe - caller must ensure buffer is valid)
    pub unsafe fn to_vec(&self) -> Vec<u8> {
        if self.data.is_null() {
            return Vec::new();
        }
        Vec::from_raw_parts(self.data, self.len, self.capacity)
    }

    /// Free the buffer
    pub unsafe fn free(&mut self) {
        if !self.data.is_null() {
            // Zeroize before freeing
            let slice = slice::from_raw_parts_mut(self.data, self.len);
            slice.zeroize();
            
            let _ = Vec::from_raw_parts(self.data, self.len, self.capacity);
            self.data = ptr::null_mut();
            self.len = 0;
            self.capacity = 0;
        }
    }
}

/// Create a new secure context
///
/// # Arguments
/// * `password` - Master password (can be null for random key)
/// * `password_len` - Length of password
/// * `context` - Output pointer to context handle
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_context_create(
    password: *const u8,
    password_len: usize,
    context: *mut *mut SibnaContext,
) -> SibnaResult {
    if context.is_null() {
        return SibnaResult::InvalidArgument;
    }

    let password_slice = if password.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(password, password_len) })
    };

    let config = Config::default();
    
    match crate::SecureContext::new(config, password_slice) {
        Ok(ctx) => {
            let ctx_ptr = Box::into_raw(Box::new(ctx));
            unsafe { *context = ctx_ptr as *mut _; }
            SibnaResult::Ok
        }
        Err(_) => SibnaResult::InternalError,
    }
}

/// Destroy a secure context
///
/// # Arguments
/// * `context` - Context handle to destroy
#[no_mangle]
pub extern "C" fn sibna_context_destroy(context: *mut SibnaContext) {
    if !context.is_null() {
        unsafe {
            let _ = Box::from_raw(context as *mut crate::SecureContext);
        }
    }
}

/// Set the device link credentials for a child device
///
/// # Arguments
/// * `context` - Valid context handle
/// * `device_id` - ID of this device
/// * `root_key` - 32-byte Ed25519 root identity key
/// * `signature` - 64-byte Ed25519 signature of (device_identity_key || device_id)
#[no_mangle]
pub extern "C" fn sibna_context_set_device_link(
    context: *mut SibnaContext,
    device_id: u32,
    root_key: *const u8,
    signature: *const u8,
) -> SibnaResult {
    if context.is_null() || root_key.is_null() || signature.is_null() {
        return SibnaResult::InvalidArgument;
    }

    let ctx = unsafe { &*(context as *const crate::SecureContext) };
    
    let mut root_arr = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(root_key, root_arr.as_mut_ptr(), 32); }
    
    let mut sig_arr = [0u8; 64];
    unsafe { std::ptr::copy_nonoverlapping(signature, sig_arr.as_mut_ptr(), 64); }

    match ctx.set_device_link(device_id, &root_arr, &sig_arr) {
        Ok(_) => SibnaResult::Ok,
        Err(_) => SibnaResult::InternalError,
    }
}

/// Get protocol version
///
/// # Arguments
/// * `version` - Output buffer for version string
/// * `version_len` - Length of output buffer
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_version(
    version: *mut c_char,
    version_len: usize,
) -> SibnaResult {
    if version.is_null() {
        return SibnaResult::InvalidArgument;
    }

    let version_str = crate::VERSION;
    let version_cstr = match CString::new(version_str) {
        Ok(s) => s,
        Err(_) => return SibnaResult::InternalError,
    };

    let version_bytes = version_cstr.as_bytes_with_nul();
    
    if version_bytes.len() > version_len {
        return SibnaResult::BufferTooSmall;
    }

    unsafe {
        ptr::copy_nonoverlapping(
            version_bytes.as_ptr() as *const c_char,
            version,
            version_bytes.len(),
        );
    }

    SibnaResult::Ok
}

/// Encrypt data
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
/// * `plaintext_len` - Length of plaintext
/// * `associated_data` - Additional authenticated data (can be null)
/// * `ad_len` - Length of associated data
/// * `ciphertext` - Output buffer for ciphertext
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_encrypt(
    key: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    associated_data: *const u8,
    ad_len: usize,
    ciphertext: *mut ByteBuffer,
) -> SibnaResult {
    if key.is_null() || plaintext.is_null() || ciphertext.is_null() {
        return SibnaResult::InvalidArgument;
    }

    let key_slice = unsafe { slice::from_raw_parts(key, KEY_LENGTH) };
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };
    let ad_slice = if associated_data.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(associated_data, ad_len) }
    };

    let handler = match CryptoHandler::new(key_slice) {
        Ok(h) => h,
        Err(_) => return SibnaResult::InvalidKey,
    };

    match handler.encrypt(plaintext_slice, ad_slice) {
        Ok(ct) => {
            unsafe {
                *ciphertext = ByteBuffer::new(ct);
            }
            SibnaResult::Ok
        }
        Err(_) => SibnaResult::EncryptionFailed,
    }
}

/// Decrypt data
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `ciphertext` - Data to decrypt
/// * `ciphertext_len` - Length of ciphertext
/// * `associated_data` - Additional authenticated data (can be null)
/// * `ad_len` - Length of associated data
/// * `plaintext` - Output buffer for plaintext
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_decrypt(
    key: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    associated_data: *const u8,
    ad_len: usize,
    plaintext: *mut ByteBuffer,
) -> SibnaResult {
    if key.is_null() || ciphertext.is_null() || plaintext.is_null() {
        return SibnaResult::InvalidArgument;
    }

    let key_slice = unsafe { slice::from_raw_parts(key, KEY_LENGTH) };
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };
    let ad_slice = if associated_data.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(associated_data, ad_len) }
    };

    let handler = match CryptoHandler::new(key_slice) {
        Ok(h) => h,
        Err(_) => return SibnaResult::InvalidKey,
    };

    match handler.decrypt(ciphertext_slice, ad_slice) {
        Ok(pt) => {
            unsafe {
                *plaintext = ByteBuffer::new(pt);
            }
            SibnaResult::Ok
        }
        Err(crate::crypto::CryptoError::AuthenticationFailed) => {
            SibnaResult::AuthenticationFailed
        }
        Err(_) => SibnaResult::DecryptionFailed,
    }
}

/// Generate random bytes
///
/// # Arguments
/// * `len` - Number of bytes to generate
/// * `output` - Output buffer
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_random_bytes(
    len: usize,
    output: *mut u8,
) -> SibnaResult {
    if output.is_null() {
        return SibnaResult::InvalidArgument;
    }

    let mut rng = match SecureRandom::new() {
        Ok(r) => r,
        Err(_) => return SibnaResult::InternalError,
    };

    let output_slice = unsafe { slice::from_raw_parts_mut(output, len) };
    rng.fill_bytes(output_slice);

    SibnaResult::Ok
}

/// Generate a 32-byte encryption key
///
/// # Arguments
/// * `key` - Output buffer for key (must be 32 bytes)
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_generate_key(
    key: *mut u8,
) -> SibnaResult {
    if key.is_null() {
        return SibnaResult::InvalidArgument;
    }

    let mut rng = match SecureRandom::new() {
        Ok(r) => r,
        Err(_) => return SibnaResult::InternalError,
    };

    let key_slice = unsafe { slice::from_raw_parts_mut(key, KEY_LENGTH) };
    rng.fill_bytes(key_slice);

    SibnaResult::Ok
}

/// Free a byte buffer
///
/// # Arguments
/// * `buffer` - Buffer to free
#[no_mangle]
pub extern "C" fn sibna_free_buffer(buffer: *mut ByteBuffer) {
    if !buffer.is_null() {
        unsafe {
            (*buffer).free();
        }
    }
}

// FIX: Thread-local last error storage for FFI callers
thread_local! {
    static LAST_ERROR: RefCell<String> = RefCell::new(String::new());
}

/// Set the thread-local last error message (internal use)
fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| { *e.borrow_mut() = msg.to_string(); });
}

/// Get the last error message
///
/// # Arguments
/// * `buffer` - Output buffer for error message  
/// * `buffer_len` - Length of output buffer
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_last_error(
    buffer: *mut c_char,
    buffer_len: usize,
) -> SibnaResult {
    // FIX: Returns actual last error message from thread-local storage
    let error_msg_owned = LAST_ERROR.with(|e| {
        let s = e.borrow();
        if s.is_empty() { "No error\0".to_string() } else { format!("{}\0", s) }
    });
    let error_msg = error_msg_owned.as_str();
    
    if buffer.is_null() {
        return SibnaResult::InvalidArgument;
    }

    if error_msg.len() > buffer_len {
        return SibnaResult::BufferTooSmall;
    }

    unsafe {
        ptr::copy_nonoverlapping(
            error_msg.as_ptr() as *const c_char,
            buffer,
            error_msg.len(),
        );
    }

    SibnaResult::Ok
}

/// Create a new session
///
/// # Arguments
/// * `context` - Secure context handle
/// * `peer_id` - Peer identifier
/// * `peer_id_len` - Length of peer ID
/// * `session` - Output session handle
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_session_create(
    context: *mut SibnaContext,
    peer_id: *const u8,
    peer_id_len: usize,
    session: *mut *mut SibnaSession,
) -> SibnaResult {
    if context.is_null() || peer_id.is_null() || session.is_null() {
        return SibnaResult::InvalidArgument;
    }

    let ctx = unsafe { &*(context as *mut crate::SecureContext) };
    let peer_id_slice = unsafe { slice::from_raw_parts(peer_id, peer_id_len) };

    match ctx.create_session(peer_id_slice) {
        Ok(handle) => {
            let session_ptr = Box::into_raw(Box::new(handle));
            unsafe { *session = session_ptr as *mut _; }
            SibnaResult::Ok
        }
        Err(e) => map_error(e),
    }
}

/// Destroy a session
///
/// # Arguments
/// * `session` - Session handle to destroy
#[no_mangle]
pub extern "C" fn sibna_session_destroy(session: *mut SibnaSession) {
    if !session.is_null() {
        unsafe {
            let _ = Box::from_raw(session as *mut crate::SessionHandle);
        }
    }
}


/// Map ProtocolError to SibnaResult
fn map_error(error: ProtocolError) -> SibnaResult {
    let msg = error.to_string();
    set_last_error(&msg);
    match error {
        ProtocolError::InvalidArgument => SibnaResult::InvalidArgument,
        ProtocolError::InvalidKeyLength | ProtocolError::InvalidKey => SibnaResult::InvalidKey,
        ProtocolError::EncryptionFailed => SibnaResult::EncryptionFailed,
        ProtocolError::DecryptionFailed => SibnaResult::DecryptionFailed,
        ProtocolError::OutOfMemory => SibnaResult::OutOfMemory,
        ProtocolError::InvalidState => SibnaResult::InvalidState,
        ProtocolError::SessionNotFound => SibnaResult::SessionNotFound,
        ProtocolError::KeyNotFound => SibnaResult::KeyNotFound,
        ProtocolError::RateLimitExceeded => SibnaResult::RateLimitExceeded,
        ProtocolError::InvalidCiphertext => SibnaResult::InvalidCiphertext,
        ProtocolError::AuthenticationFailed => SibnaResult::AuthenticationFailed,
        _ => SibnaResult::InternalError,
    }
}

// ============================================================
// NEW: Identity & Prekey Bundle Functions
// ============================================================

/// Protocol output layout for identity key generation.
///
/// On success, fills `ed25519_pub_out` (32 bytes) with the Ed25519 public key
/// and `x25519_pub_out` (32 bytes) with the X25519 DH public key.
/// These should be registered as the user's identity on the prekey server.
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_generate_identity(
    context: *mut SibnaContext,
    ed25519_pub_out: *mut u8,
    x25519_pub_out: *mut u8,
) -> SibnaResult {
    if context.is_null() || ed25519_pub_out.is_null() || x25519_pub_out.is_null() {
        set_last_error("Null pointer argument");
        return SibnaResult::InvalidArgument;
    }

    let ctx = unsafe { &*(context as *mut crate::SecureContext) };

    match ctx.generate_identity() {
        Ok(keypair) => {
            unsafe {
                ptr::copy_nonoverlapping(keypair.ed25519_public.as_ptr(), ed25519_pub_out, 32);
                ptr::copy_nonoverlapping(keypair.x25519_public.as_ptr(), x25519_pub_out, 32);
            }
            SibnaResult::Ok
        }
        Err(e) => map_error(e),
    }
}

/// Generate a prekey bundle from the context's keystore.
///
/// The bundle is serialized using the `PreKeyBundle::to_bytes()` format
/// (identity_key || signed_prekey || signature || has_opk || [opk] || timestamp)
/// and written to `bundle_out`.
///
/// Call this after `sibna_generate_identity` — it will fail if no identity
/// or signed prekey is available in the context.
///
/// # Returns
/// `SibnaResult::Ok` on success, `SibnaResult::KeyNotFound` if no identity or signed prekey.
#[no_mangle]
pub extern "C" fn sibna_generate_prekey_bundle(
    context: *mut SibnaContext,
    bundle_out: *mut ByteBuffer,
) -> SibnaResult {
    if context.is_null() || bundle_out.is_null() {
        set_last_error("Null pointer argument");
        return SibnaResult::InvalidArgument;
    }

    let ctx = unsafe { &*(context as *mut crate::SecureContext) };
    let keystore = ctx.keystore.read();

    let bytes = match keystore.generate_prekey_bundle_bytes() {
        Ok(b) => b,
        Err(e) => return map_error(e),
    };

    drop(keystore);

    unsafe {
        *bundle_out = ByteBuffer::new(bytes);
    }
    SibnaResult::Ok
}


/// Perform X3DH handshake using a peer's prekey bundle.
///
/// `bundle_bytes` / `bundle_len` — serialized `PreKeyBundle` (from `sibna_generate_prekey_bundle`)
/// `peer_id` / `peer_id_len` — opaque peer identifier (used as session key)
/// `initiator` — non-zero if we are initiating the handshake
///
/// On success the session is stored inside `context` and can be used with
/// `sibna_session_encrypt` / `sibna_session_decrypt` using `peer_id` as the session ID.
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_perform_handshake(
    context: *mut SibnaContext,
    bundle_bytes: *const u8,
    bundle_len: usize,
    peer_id: *const u8,
    peer_id_len: usize,
    initiator: u8,
) -> SibnaResult {
    if context.is_null() || bundle_bytes.is_null() || peer_id.is_null() {
        set_last_error("Null pointer argument");
        return SibnaResult::InvalidArgument;
    }
    if bundle_len == 0 || peer_id_len == 0 || peer_id_len > 256 {
        set_last_error("Invalid buffer length");
        return SibnaResult::InvalidArgument;
    }

    let ctx = unsafe { &*(context as *mut crate::SecureContext) };
    let bundle_slice = unsafe { slice::from_raw_parts(bundle_bytes, bundle_len) };
    let peer_id_slice = unsafe { slice::from_raw_parts(peer_id, peer_id_len) };

    // Parse prekey bundle
    let bundle = match crate::handshake::PreKeyBundle::from_bytes(bundle_slice) {
        Ok(b) => b,
        Err(e) => return map_error(e),
    };

    // Validate bundle (Ed25519 signature of signed_prekey)
    if let Err(e) = bundle.validate() {
        return map_error(e);
    }

    let is_initiator = initiator != 0;

    let peer_ik: Option<&[u8]> = Some(&bundle.identity_key);
    let peer_spk: Option<&[u8]> = Some(&bundle.signed_prekey);
    let peer_opk: Option<&[u8]> = bundle.onetime_prekey.as_ref().map(|k| k.as_ref());

    match ctx.perform_handshake(
        peer_id_slice,
        is_initiator,
        peer_ik,
        peer_spk,
        peer_opk,
        None,
    ) {
        Ok(_) => SibnaResult::Ok,
        Err(e) => map_error(e),
    }
}

/// Encrypt a message through a Double Ratchet session.
///
/// `session_id` / `session_id_len` — the peer ID used in `sibna_session_create` or
///   returned from `sibna_perform_handshake`.
/// `plaintext` / `plaintext_len` — data to encrypt (must be ≥ 1 byte).
/// `associated_data` / `ad_len` — optional AAD (pass NULL / 0 for none).
/// `ciphertext_out` — receives the allocated ciphertext buffer; caller must free with
///   `sibna_free_buffer`.
///
/// # Returns
/// `SibnaResult::Ok` on success
#[no_mangle]
pub extern "C" fn sibna_session_encrypt(
    context: *mut SibnaContext,
    session_id: *const u8,
    session_id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    associated_data: *const u8,
    ad_len: usize,
    ciphertext_out: *mut ByteBuffer,
) -> SibnaResult {
    if context.is_null() || session_id.is_null() || plaintext.is_null() || ciphertext_out.is_null() {
        set_last_error("Null pointer argument");
        return SibnaResult::InvalidArgument;
    }
    if session_id_len == 0 || session_id_len > 256 {
        set_last_error("Invalid session_id length");
        return SibnaResult::InvalidArgument;
    }
    if plaintext_len == 0 {
        set_last_error("Plaintext must not be empty");
        return SibnaResult::InvalidArgument;
    }

    let ctx = unsafe { &*(context as *mut crate::SecureContext) };
    let session_id_slice = unsafe { slice::from_raw_parts(session_id, session_id_len) };
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };
    let ad_slice: Option<&[u8]> = if associated_data.is_null() || ad_len == 0 {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(associated_data, ad_len) })
    };

    match ctx.encrypt_message(session_id_slice, plaintext_slice, ad_slice) {
        Ok(ct) => {
            unsafe {
                *ciphertext_out = ByteBuffer::new(ct);
            }
            SibnaResult::Ok
        }
        Err(e) => map_error(e),
    }
}

/// Decrypt a message through a Double Ratchet session.
///
/// `session_id` / `session_id_len` — session identifier.
/// `ciphertext` / `ciphertext_len` — data to decrypt.
/// `associated_data` / `ad_len` — optional AAD (must match what was used for encryption).
/// `plaintext_out` — receives the allocated plaintext buffer; caller must free with
///   `sibna_free_buffer`.
///
/// # Returns
/// `SibnaResult::Ok` on success, `SibnaResult::AuthenticationFailed` on tampered data,
/// `SibnaResult::SessionNotFound` if the session does not exist.
#[no_mangle]
pub extern "C" fn sibna_session_decrypt(
    context: *mut SibnaContext,
    session_id: *const u8,
    session_id_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    associated_data: *const u8,
    ad_len: usize,
    plaintext_out: *mut ByteBuffer,
) -> SibnaResult {
    if context.is_null() || session_id.is_null() || ciphertext.is_null() || plaintext_out.is_null() {
        set_last_error("Null pointer argument");
        return SibnaResult::InvalidArgument;
    }
    if session_id_len == 0 || session_id_len > 256 {
        set_last_error("Invalid session_id length");
        return SibnaResult::InvalidArgument;
    }
    if ciphertext_len < 29 { // HEADER_SIZE(56) - but we need at minimum nonce+tag+1
        set_last_error("Ciphertext too short");
        return SibnaResult::InvalidCiphertext;
    }

    let ctx = unsafe { &*(context as *mut crate::SecureContext) };
    let session_id_slice = unsafe { slice::from_raw_parts(session_id, session_id_len) };
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };
    let ad_slice: Option<&[u8]> = if associated_data.is_null() || ad_len == 0 {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(associated_data, ad_len) })
    };

    match ctx.decrypt_message(session_id_slice, ciphertext_slice, ad_slice) {
        Ok(pt) => {
            unsafe {
                *plaintext_out = ByteBuffer::new(pt);
            }
            SibnaResult::Ok
        }
        Err(e) => map_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_buffer() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer = ByteBuffer::new(data);
        
        assert_eq!(buffer.len, 5);
        assert!(!buffer.data.is_null());
        
        unsafe {
            buffer.free();
        }
    }

    #[test]
    fn test_generate_key() {
        let mut key = [0u8; 32];
        let result = sibna_generate_key(key.as_mut_ptr());
        
        assert_eq!(result, SibnaResult::Ok);
        assert!(!key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut key = [0x42u8; 32];
        // Make key valid (not all same byte)
        key[0] = 0x41;
        
        let plaintext = b"Hello, World!";
        let mut ciphertext = ByteBuffer::empty();
        
        let result = sibna_encrypt(
            key.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            ptr::null(),
            0,
            &mut ciphertext,
        );
        
        assert_eq!(result, SibnaResult::Ok);
        assert!(!ciphertext.data.is_null());
        
        let mut decrypted = ByteBuffer::empty();
        let result = sibna_decrypt(
            key.as_ptr(),
            ciphertext.data,
            ciphertext.len,
            ptr::null(),
            0,
            &mut decrypted,
        );
        
        assert_eq!(result, SibnaResult::Ok);
        
        unsafe {
            let decrypted_vec = decrypted.to_vec();
            assert_eq!(decrypted_vec, plaintext);
            
            ciphertext.free();
            decrypted.free();
        }
    }

    #[test]
    fn test_random_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        
        sibna_random_bytes(32, buf1.as_mut_ptr());
        sibna_random_bytes(32, buf2.as_mut_ptr());
        
        assert_ne!(buf1, buf2);
    }
}
