//! Kani Model Checking Harnesses for Double Ratchet
//!
//! Run with: cargo kani --harness kani_ratchet_replay_detection --default-unwind 12

#[cfg(kani)]
mod harnesses {
    use sibna_core::{Config, HandshakeRole, ratchet::DoubleRatchetSession};
    use sibna_core::error::ProtocolError;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[kani::proof]
    fn kani_ratchet_replay_detection() {
        let shared_secret: [u8; 32] = kani::any();
        let sk1_bytes: [u8; 32] = kani::any();
        let sk2_bytes: [u8; 32] = kani::any();

        let sk1 = StaticSecret::from(sk1_bytes);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::from(sk2_bytes);
        let pk2 = PublicKey::from(&sk2);

        kani::assume(!shared_secret.iter().all(|&b| b == 0));

        let config = Config {
            max_skipped_messages: 2000,
            ..Config::default()
        };

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, config.clone(), HandshakeRole::Initiator
        ).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, config.clone(), HandshakeRole::Responder
        ).unwrap();

        let plaintext = b"test";
        let ad = b"ad";

        let ct = s1.encrypt(plaintext, ad).unwrap();

        // First decrypt should succeed
        let pt1 = s2.decrypt(&ct, ad).unwrap();
        kani::assert(pt1 == plaintext, "First decrypt must succeed");

        // Second decrypt of same ciphertext MUST fail with ReplayAttackDetected
        let result = s2.decrypt(&ct, ad);
        kani::assert(
            matches!(result, Err(ProtocolError::ReplayAttackDetected)),
            "Replay must be detected"
        );
    }

    #[kani::proof]
    fn kani_ratchet_encrypt_decrypt_roundtrip() {
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

        let plaintext: [u8; 32] = kani::any();
        let ad: [u8; 16] = kani::any();

        let ct = s1.encrypt(&plaintext, &ad).unwrap();
        let pt = s2.decrypt(&ct, &ad).unwrap();

        kani::assert(pt == plaintext.to_vec(), "Roundtrip must preserve plaintext");
    }

    #[kani::proof]
    fn kani_ratchet_skip_keys_bounds() {
        let shared_secret: [u8; 32] = kani::any();
        let sk1_bytes: [u8; 32] = kani::any();
        let sk2_bytes: [u8; 32] = kani::any();

        let sk1 = StaticSecret::from(sk1_bytes);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::from(sk2_bytes);
        let pk2 = PublicKey::from(&sk2);

        kani::assume(!shared_secret.iter().all(|&b| b == 0));

        // Small max_skip to test bounds quickly
        let config = Config {
            max_skipped_messages: 10,
            ..Config::default()
        };

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, config.clone(), HandshakeRole::Initiator
        ).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, config.clone(), HandshakeRole::Responder
        ).unwrap();

        let ad = b"ad";

        // Send 15 messages (exceeds max_skip of 10)
        for _ in 0..15 {
            let _ = s1.encrypt(b"skip", ad);
        }
        let ct = s1.encrypt(b"final", ad).unwrap();

        let result = s2.decrypt(&ct, ad);

        // Should fail with MaxSkippedMessagesExceeded
        kani::assert(
            matches!(result, Err(ProtocolError::MaxSkippedMessagesExceeded)),
            "Excessive skips must be rejected"
        );
    }

    #[kani::proof]
    fn kani_ratchet_dh_rotation_changes_keys() {
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

        // Get initial state summary
        let summary1 = s1.state_summary();
        let summary2 = s2.state_summary();

        // Force a DH rotation by sending many messages (exceeds chain length)
        for _ in 0..config.max_chain_messages + 1 {
            let _ = s1.encrypt(b"force_rotate", ad);
        }

        let summary1_after = s1.state_summary();
        let summary2_after = s2.state_summary();

        // Ratchet count should have increased
        kani::assert(
            summary1_after.ratchet_count > summary1.ratchet_count,
            "DH rotation must increase ratchet count"
        );
    }
}