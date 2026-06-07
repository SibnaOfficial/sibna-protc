#![no_main]

use libfuzzer_sys::fuzz_target;
use sibna_core::ratchet::{RatchetMessage, RatchetHeader, ENCRYPTED_HEADER_SIZE, HEADER_SIZE};
use sibna_core::crypto::{CryptoHandler, KeyGenerator};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_SIZE {
        return;
    }

    let _ = RatchetMessage::from_bytes(data);

    if data.len() >= ENCRYPTED_HEADER_SIZE + 29 {
        if let Ok(key) = KeyGenerator::generate_key() {
            if let Ok(handler) = CryptoHandler::new(&key) {
                let header_key = *key.as_ref();
                let _ = RatchetMessage::from_bytes_encrypted(data, &header_key);
            }
        }
    }
});