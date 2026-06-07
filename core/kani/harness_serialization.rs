//! Kani Model Checking Harnesses for Serialization
//!
//! Run with: cargo kani --harness kani_serialize_deserialize_state --default-unwind 12

#[cfg(kani)]
mod harnesses {
    use sibna_core::{Config, HandshakeRole, ratchet::DoubleRatchetSession};
    use x25519_dalek::{PublicKey, StaticSecret};

    #[kani::proof]
    fn kani_serialize_deserialize_state() {
        let shared_secret: [u8; 32] = kani::any();
        let sk1_bytes: [u8; 32] = kani::any();
        let sk2_bytes: [u8; 32] = kani::any();

        let sk1 = StaticSecret::from(sk1_bytes);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::from(sk2_bytes);
        let pk2 = PublicKey::from(&sk2);

        kani::assume(!shared_secret.iter().all(|&b| b == 0));

        let config = Config::default();

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, config.clone(), HandshakeRole::Initiator
        ).unwrap();

        // Send a few messages
        let ad = b"ad";
        for i in 0..5 {
            let _ = s1.encrypt(format!("msg_{}", i).as_bytes(), ad).unwrap();
        }

        // Serialize
        let serialized = s1.serialize_state().unwrap();

        // Deserialize into new session
        let s1_restored = DoubleRatchetSession::new(config.clone()).unwrap();
        let result = s1_restored.deserialize_state(&serialized);

        kani::assert(result.is_ok(), "Deserialization must succeed");

        // Restored session must be able to send and receive
        let ct = s1_restored.encrypt(b"after_restore", ad).unwrap();

        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, config.clone(), HandshakeRole::Responder
        ).unwrap();

        // s2 needs to catch up to where s1 was
        for i in 0..5 {
            let _ = s2.decrypt(&s1.encrypt(format!("msg_{}", i).as_bytes(), ad).unwrap(), ad).unwrap();
        }

        let pt = s2.decrypt(&ct, ad).unwrap();
        kani::assert(pt == b"after_restore", "Restored session must work correctly");
    }

    #[kani::proof]
    fn kani_session_state_consistency() {
        let shared_secret: [u8; 32] = kani::any();
        let sk1_bytes: [u8; 32] = kani::any();
        let sk2_bytes: [u8; 32] = kani::any();

        let sk1 = StaticSecret::from(sk1_bytes);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::from(sk2_bytes);
        let pk2 = PublicKey::from(&sk2);

        kani::assume(!shared_secret.iter().all(|&b| b == 0));

        let config = Config::default();

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, config.clone(), HandshakeRole::Initiator
        ).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, config.clone(), HandshakeRole::Responder
        ).unwrap();

        let ad = b"ad";
        let plaintext = b"test message";

        // Encrypt from s1, decrypt on s2
        let ct = s1.encrypt(plaintext, ad).unwrap();
        let pt = s2.decrypt(&ct, ad).unwrap();

        kani::assert(pt == plaintext, "Basic encrypt/decrypt must work");

        // State counters should be consistent
        let (sent1, recv1) = s1.message_stats();
        let (sent2, recv2) = s2.message_stats();

        kani::assert(sent1 == 1, "s1 should have sent 1 message");
        kani::assert(recv2 == 1, "s2 should have received 1 message");
    }
}