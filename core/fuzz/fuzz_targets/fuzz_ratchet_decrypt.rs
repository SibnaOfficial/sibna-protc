#![no_main]

use libfuzzer_sys::fuzz_target;
use sibna_core::{Config, HandshakeRole, ratchet::DoubleRatchetSession};
use x25519_dalek::{PublicKey, StaticSecret};

fuzz_target!(|data: &[u8]| {
    if data.len() < 100 {
        return;
    }

    let shared_secret: [u8; 32] = match data[..32].try_into() { Ok(k) => k, Err(_) => return };
    let local_dh_bytes: [u8; 32] = match data[32..64].try_into() { Ok(k) => k, Err(_) => return };
    let remote_dh_bytes: [u8; 32] = match data[64..96].try_into() { Ok(k) => k, Err(_) => return };

    let local_dh = StaticSecret::from(local_dh_bytes);
    let remote_dh = PublicKey::from(&StaticSecret::from(remote_dh_bytes));

    if shared_secret.iter().all(|&b| b == 0) {
        return;
    }

    let alice = match DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        local_dh,
        remote_dh,
        Config::default(),
        HandshakeRole::Initiator,
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let bob = match DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        StaticSecret::from(remote_dh_bytes),
        PublicKey::from(&StaticSecret::from(local_dh_bytes)),
        Config::default(),
        HandshakeRole::Responder,
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let plaintext = &data[96..];
    let ad = b"fuzz_ad";

    if let Ok(ct) = alice.encrypt(plaintext, ad) {
        let _ = bob.decrypt(&ct, ad);
    }

    if data.len() > 100 {
        let _ = bob.decrypt(&data[100..], ad);
    }
});