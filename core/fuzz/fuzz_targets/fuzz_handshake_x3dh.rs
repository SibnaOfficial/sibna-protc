#![no_main]

use libfuzzer_sys::fuzz_target;
use sibna_core::handshake::PreKeyBundle;

fuzz_target!(|data: &[u8]| {
    if data.len() < 325 {
        return;
    }

    let _ = PreKeyBundle::from_bytes(data);
});