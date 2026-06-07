#![no_main]

use libfuzzer_sys::fuzz_target;
use sibna_core::crypto::CryptoHandler;

fuzz_target!(|data: &[u8]| {
    if data.len() != 32 {
        return;
    }

    let key: [u8; 32] = match data.try_into() {
        Ok(k) => k,
        Err(_) => return,
    };

    let _ = CryptoHandler::new(&key);
});