#![no_main]

use libfuzzer_sys::fuzz_target;
use sibna_core::crypto::{pad_message, unpad_message, PaddingMode};

fuzz_target!(|data: &[u8]| {
    for mode in [
        PaddingMode::None,
        PaddingMode::Standard,
        PaddingMode::Quantum,
    ] {
        if let Ok(padded) = pad_message(data, mode) {
            let _ = unpad_message(&padded);
        }
    }
});