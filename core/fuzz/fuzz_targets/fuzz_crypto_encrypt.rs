#![no_main]

use libfuzzer_sys::fuzz_target;
use sibna_core::crypto::{CryptoHandler, KeyGenerator};

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    let key_bytes: [u8; 32] = match data[..32].try_into() {
        Ok(k) => k,
        Err(_) => return,
    };

    let handler = match CryptoHandler::new(&key_bytes) {
        Ok(h) => h,
        Err(_) => return,
    };

    let plaintext = &data[32..];
    let ad = b"fuzz_ad";

    if let Ok(ct) = handler.encrypt(plaintext, ad) {
        let _ = handler.decrypt(&ct, ad);
    }
});