#![no_main]

use libfuzzer_sys::fuzz_target;
use sibna_core::{Config, HandshakeRole, ratchet::DoubleRatchetSession};
use x25519_dalek::{PublicKey, StaticSecret};

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
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

    let session = match DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        local_dh,
        remote_dh,
        Config::default(),
        HandshakeRole::Initiator,
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = session.encrypt(b"test", b"ad");

    let serialized = match session.serialize_state() {
        Ok(s) => s,
        Err(_) => return,
    };

    let new_session = match DoubleRatchetSession::new(Config::default()) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = new_session.deserialize_state(&serialized);
});