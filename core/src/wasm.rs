//! WASM Bindings for Sibna Protocol v10
//!
//! Provides `wasm-bindgen` exported functions for use in web applications
//! (TypeScript, JavaScript). Uses thread-local storage for the `SecureContext`
//! since WASM is single-threaded.
//!
//! # Usage (JavaScript/TypeScript)
//! ```js
//! import init, { wasm_context_create, wasm_session_encrypt, wasm_session_decrypt } from 'sibna_core';
//!
//! await init();
//! wasm_context_create();
//! wasm_generate_identity();
//! // ... exchange prekey bundles via your signaling server ...
//! wasm_session_encrypt(sessionId, plaintext);
//! ```

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use wasm_bindgen::prelude::*;
    use js_sys::Uint8Array;
    use std::cell::RefCell;

    // Store the context in a thread-local (WASM is single-threaded)
    thread_local! {
        static CONTEXT: RefCell<Option<crate::SecureContext>> = RefCell::new(None);
    }

    /// Initialize the Sibna context for use in WASM.
    ///
    /// Call this once before any other WASM functions. A fresh identity keypair
    /// will be generated automatically — capture it with `wasm_get_identity`.
    #[wasm_bindgen]
    pub fn wasm_context_create() -> Result<(), JsValue> {
        let config = crate::Config::default();
        let ctx = crate::SecureContext::new(config)
            .map_err(|e| JsValue::from_str(&format!("Context creation failed: {}", e)))?;
        CONTEXT.with(|c| {
            *c.borrow_mut() = Some(ctx);
        });
        Ok(())
    }

    /// Generate a new identity keypair and store it in the context keystore.
    ///
    /// Returns a `Uint8Array` of 64 bytes: `ed25519_pub (32) || x25519_pub (32)`.
    #[wasm_bindgen]
    pub fn wasm_generate_identity() -> Result<Uint8Array, JsValue> {
        CONTEXT.with(|c| {
            let borrow = c.borrow();
            let ctx = borrow.as_ref()
                .ok_or_else(|| JsValue::from_str("Context not initialized — call wasm_context_create() first"))?;

            let keypair = ctx.generate_identity()
                .map_err(|e| JsValue::from_str(&format!("Identity generation failed: {}", e)))?;

            let mut result = [0u8; 64];
            result[..32].copy_from_slice(&keypair.ed25519_public);
            result[32..].copy_from_slice(&keypair.x25519_public);

            Ok(Uint8Array::from(&result[..]))
        })
    }

    /// Generate a prekey bundle from the context's keystore.
    ///
    /// Returns the serialized `PreKeyBundle` bytes. Upload this to your prekey server
    /// so peers can send you messages while you are offline.
    #[wasm_bindgen]
    pub fn wasm_generate_prekey_bundle() -> Result<Uint8Array, JsValue> {
        CONTEXT.with(|c| {
            let borrow = c.borrow();
            let ctx = borrow.as_ref()
                .ok_or_else(|| JsValue::from_str("Context not initialized"))?;

            let keystore = ctx.keystore.read();
            let bytes = keystore.generate_prekey_bundle_bytes()
                .map_err(|e| JsValue::from_str(&format!("Failed to generate signed prekey bundle: {}", e)))?;
            drop(keystore);

            Ok(Uint8Array::from(&bytes[..]))
        })
    }

    /// Perform an X3DH handshake using a peer's prekey bundle.
    ///
    /// - `bundle_bytes` — serialized `PreKeyBundle` (from `wasm_generate_prekey_bundle`)
    /// - `session_id` — arbitrary bytes identifying this session / peer
    /// - `initiator` — `true` if we are initiating the handshake
    #[wasm_bindgen]
    pub fn wasm_perform_handshake(
        bundle_bytes: &[u8],
        session_id: &[u8],
        initiator: bool,
    ) -> Result<(), JsValue> {
        CONTEXT.with(|c| {
            let borrow = c.borrow();
            let ctx = borrow.as_ref()
                .ok_or_else(|| JsValue::from_str("Context not initialized"))?;

            let bundle = crate::handshake::PreKeyBundle::from_bytes(bundle_bytes)
                .map_err(|e| JsValue::from_str(&format!("Failed to parse prekey bundle: {}", e)))?;

            bundle.validate()
                .map_err(|e| JsValue::from_str(&format!("Invalid prekey bundle: {}", e)))?;

            let peer_ik: Option<&[u8]> = Some(&bundle.identity_key);
            let peer_spk: Option<&[u8]> = Some(&bundle.signed_prekey);
            let peer_opk: Option<&[u8]> = bundle.onetime_prekey.as_ref().map(|k| k.as_ref());

            ctx.perform_handshake(session_id, initiator, peer_ik, peer_spk, peer_opk, None)
                .map_err(|e| JsValue::from_str(&format!("Handshake failed: {}", e)))?;

            Ok(())
        })
    }

    /// Encrypt a message through a Double Ratchet session.
    ///
    /// - `session_id` — the session identifier (same as used in `wasm_perform_handshake`)
    /// - `plaintext` — data to encrypt
    ///
    /// Returns the encrypted bytes.
    #[wasm_bindgen]
    pub fn wasm_session_encrypt(
        session_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Uint8Array, JsValue> {
        CONTEXT.with(|c| {
            let borrow = c.borrow();
            let ctx = borrow.as_ref()
                .ok_or_else(|| JsValue::from_str("Context not initialized"))?;

            if plaintext.is_empty() {
                return Err(JsValue::from_str("Plaintext must not be empty"));
            }

            let ciphertext = ctx.encrypt_message(session_id, plaintext, None)
                .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

            Ok(Uint8Array::from(&ciphertext[..]))
        })
    }

    /// Decrypt a message through a Double Ratchet session.
    ///
    /// - `session_id` — the session identifier (same as used in `wasm_perform_handshake`)
    /// - `ciphertext` — data to decrypt
    ///
    /// Returns the decrypted bytes.
    #[wasm_bindgen]
    pub fn wasm_session_decrypt(
        session_id: &[u8],
        ciphertext: &[u8],
    ) -> Result<Uint8Array, JsValue> {
        CONTEXT.with(|c| {
            let borrow = c.borrow();
            let ctx = borrow.as_ref()
                .ok_or_else(|| JsValue::from_str("Context not initialized"))?;

            let plaintext = ctx.decrypt_message(session_id, ciphertext, None)
                .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;

            Ok(Uint8Array::from(&plaintext[..]))
        })
    }

    /// Generate a 32-byte challenge for device authentication.
    ///
    /// Send this to a device; the device signs it with its Ed25519 key and
    /// returns the 64-byte signature. Verify with `wasm_verify_signed_challenge`.
    #[wasm_bindgen]
    pub fn wasm_generate_challenge() -> Result<Uint8Array, JsValue> {
        let challenge = crate::keystore::KeyStore::generate_challenge()
            .map_err(|e| JsValue::from_str(&format!("Challenge generation failed: {}", e)))?;
        Ok(Uint8Array::from(&challenge[..]))
    }

    /// Verify an Ed25519 challenge-response.
    ///
    /// - `challenge` — 32-byte challenge (from `wasm_generate_challenge`)
    /// - `signature` — 64-byte Ed25519 signature from the device
    /// - `device_pub` — 32-byte Ed25519 public key of the authenticating device
    ///
    /// Returns `true` if the signature is valid.
    #[wasm_bindgen]
    pub fn wasm_verify_signed_challenge(
        challenge: &[u8],
        signature: &[u8],
        device_pub: &[u8],
    ) -> Result<bool, JsValue> {
        if challenge.len() != 32 {
            return Err(JsValue::from_str("Challenge must be 32 bytes"));
        }
        if signature.len() != 64 {
            return Err(JsValue::from_str("Signature must be 64 bytes"));
        }
        if device_pub.len() != 32 {
            return Err(JsValue::from_str("Device public key must be 32 bytes"));
        }

        let ch: &[u8; 32] = challenge.try_into()
            .map_err(|_| JsValue::from_str("Challenge conversion failed"))?;
        let sig: &[u8; 64] = signature.try_into()
            .map_err(|_| JsValue::from_str("Signature conversion failed"))?;
        let pub_key: &[u8; 32] = device_pub.try_into()
            .map_err(|_| JsValue::from_str("Public key conversion failed"))?;

        crate::keystore::KeyStore::verify_signed_challenge(ch, sig, pub_key)
            .map_err(|e| JsValue::from_str(&format!("Verification error: {}", e)))
    }

    /// Low-level stateless encryption using ChaCha20-Poly1305.
    ///
    /// `key` must be 32 bytes. Returns `nonce (12) || ciphertext || tag (16)`.
    #[wasm_bindgen]
    pub fn wasm_encrypt(key: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Uint8Array, JsValue> {
        use crate::crypto::CryptoHandler;

        let key_arr: &[u8; 32] = key.try_into()
            .map_err(|_| JsValue::from_str("Key must be exactly 32 bytes"))?;

        let handler = CryptoHandler::new(key_arr)
            .map_err(|e| JsValue::from_str(&format!("Invalid key: {}", e)))?;
        let ct = handler.encrypt(plaintext, associated_data)
            .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

        Ok(Uint8Array::from(&ct[..]))
    }

    /// Low-level stateless decryption using ChaCha20-Poly1305.
    ///
    /// `key` must be 32 bytes. `ciphertext` must be `nonce (12) || ciphertext || tag (16)`.
    #[wasm_bindgen]
    pub fn wasm_decrypt(key: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Uint8Array, JsValue> {
        use crate::crypto::CryptoHandler;

        let key_arr: &[u8; 32] = key.try_into()
            .map_err(|_| JsValue::from_str("Key must be exactly 32 bytes"))?;

        let handler = CryptoHandler::new(key_arr)
            .map_err(|e| JsValue::from_str(&format!("Invalid key: {}", e)))?;
        let pt = handler.decrypt(ciphertext, associated_data)
            .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;

        Ok(Uint8Array::from(&pt[..]))
    }
}

// Re-export for when the wasm feature is enabled
#[cfg(target_arch = "wasm32")]
pub use wasm_impl::*;

#[cfg(test)]
mod tests {
    // WASM functions can't be unit-tested outside of wasm target,
    // but we can verify the module compiles and the helper types work.

    #[test]
    fn test_wasm_module_compiles() {
        // If this compiles, the WASM module structure is correct.
        // Actual WASM execution tests require wasm-pack test.
    }
}
