//! Property-based tests for Sibna Protocol cryptographic properties
//!
//! Run with: cargo test --test proptest_properties -- --nocapture

use proptest::prelude::*;
use sibna_core::crypto::{CryptoHandler, KeyGenerator, pad_message, unpad_message, PaddingMode};
use sibna_core::{Config, HandshakeRole, ratchet::DoubleRatchetSession};
use x25519_dalek::{PublicKey, StaticSecret};

proptest! {
    #[test]
    fn prop_crypto_encrypt_decrypt_roundtrip(
        plaintext in any::<Vec<u8>>().prop_filter("len <= 1000 && not empty", |v| !v.is_empty() && v.len() <= 1000),
        ad in any::<Vec<u8>>().prop_filter("len <= 256", |v| v.len() <= 256),
    ) {
    let key = KeyGenerator::generate_key().unwrap();
    let handler = CryptoHandler::new(key.as_ref()).unwrap();
        let ct = handler.encrypt(&plaintext, &ad).unwrap();
        let pt = handler.decrypt(&ct, &ad).unwrap();
        prop_assert_eq!(pt, plaintext);
    }

    #[test]
    fn prop_crypto_wrong_ad_fails(
        plaintext in any::<Vec<u8>>().prop_filter("len <= 1000 && not empty", |v| !v.is_empty() && v.len() <= 1000),
        ad1 in any::<Vec<u8>>().prop_filter("len <= 256", |v| v.len() <= 256),
        ad2 in any::<Vec<u8>>().prop_filter("len <= 256", |v| v.len() <= 256),
    ) {
    let key = KeyGenerator::generate_key().unwrap();
    let handler = CryptoHandler::new(key.as_ref()).unwrap();
        let ct = handler.encrypt(&plaintext, &ad1).unwrap();
        if ad1 != ad2 {
            let result = handler.decrypt(&ct, &ad2);
            prop_assert!(result.is_err(), "Decryption should fail with wrong AD");
        }
    }

    #[test]
    fn prop_crypto_tampered_ciphertext_fails(
        plaintext in any::<Vec<u8>>().prop_filter("len <= 1000 && not empty", |v| !v.is_empty() && v.len() <= 1000),
        ad in any::<Vec<u8>>().prop_filter("len <= 256", |v| v.len() <= 256),
    ) {
    let key = KeyGenerator::generate_key().unwrap();
    let handler = CryptoHandler::new(key.as_ref()).unwrap();
        let mut ct = handler.encrypt(&plaintext, &ad).unwrap();
        if ct.len() > 28 {
            ct[28] ^= 0xFF;
        }
        let result = handler.decrypt(&ct, &ad);
        prop_assert!(result.is_err(), "Tampered ciphertext should fail");
    }

    #[test]
    fn prop_crypto_empty_plaintext_allowed(
        ad in any::<Vec<u8>>().prop_filter("len <= 256", |v| v.len() <= 256),
    ) {
    let key = KeyGenerator::generate_key().unwrap();
    let handler = CryptoHandler::new(key.as_ref()).unwrap();
        let ct = handler.encrypt(b"", &ad).unwrap();
        let pt = handler.decrypt(&ct, &ad).unwrap();
        prop_assert_eq!(pt, b"");
    }

    #[test]
    fn prop_padding_roundtrip(
        plaintext in any::<Vec<u8>>().prop_filter("len <= 5000", |v| v.len() <= 5000),
        mode in prop::sample::select(vec![
            PaddingMode::Standard,
            PaddingMode::Quantum,
        ]),
    ) {
        let padded = pad_message(&plaintext, mode).unwrap();
        let unpadded = unpad_message(&padded).unwrap();
        prop_assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn prop_padding_standard_block_aligned(
        plaintext in any::<Vec<u8>>().prop_filter("len <= 5000", |v| v.len() <= 5000),
    ) {
        let padded = pad_message(&plaintext, PaddingMode::Standard).unwrap();
        prop_assert_eq!(padded.len() % 256, 0, "Standard padding must be 256-byte aligned");
    }

    #[test]
    fn prop_padding_quantum_block_aligned(
        plaintext in any::<Vec<u8>>().prop_filter("len <= 5000", |v| v.len() <= 5000),
    ) {
        let padded = pad_message(&plaintext, PaddingMode::Quantum).unwrap();
        prop_assert_eq!(padded.len() % 65536, 0, "Quantum padding must be 64KB aligned");
    }

    #[test]
    fn prop_ratchet_encrypt_decrypt_roundtrip(
        plaintext in any::<Vec<u8>>().prop_filter("len <= 1000 && not empty", |v| !v.is_empty() && v.len() <= 1000),
        ad in any::<Vec<u8>>().prop_filter("len <= 256", |v| v.len() <= 256),
    ) {
        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, Config::default(), HandshakeRole::Initiator
        ).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, Config::default(), HandshakeRole::Responder
        ).unwrap();

        let ct = s1.encrypt(&plaintext, &ad).unwrap();
        let pt = s2.decrypt(&ct, &ad).unwrap();
        prop_assert_eq!(pt, plaintext);
    }

    #[test]
    fn prop_ratchet_replay_detection(
        plaintext in any::<Vec<u8>>().prop_filter("len <= 1000 && not empty", |v| !v.is_empty() && v.len() <= 1000),
        ad in any::<Vec<u8>>().prop_filter("len <= 256", |v| v.len() <= 256),
    ) {
        use sibna_core::error::ProtocolError;

        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, Config::default(), HandshakeRole::Initiator
        ).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, Config::default(), HandshakeRole::Responder
        ).unwrap();

        let ct = s1.encrypt(&plaintext, &ad).unwrap();
        let _ = s2.decrypt(&ct, &ad).unwrap();
        let result = s2.decrypt(&ct, &ad);
        prop_assert!(matches!(result, Err(ProtocolError::ReplayAttackDetected)),
            "Replay must be detected");
    }

    #[test]
    fn prop_ratchet_multiple_messages_order_independent(
        msgs in proptest::collection::vec(
            any::<Vec<u8>>().prop_filter("len <= 200 && not empty", |v| !v.is_empty() && v.len() <= 200),
            1..10
        ),
    ) {
        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, Config::default(), HandshakeRole::Initiator
        ).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, Config::default(), HandshakeRole::Responder
        ).unwrap();

        let ad = b"test_ad";
        let mut ciphertexts = Vec::new();
        for m in &msgs {
            ciphertexts.push(s1.encrypt(m, ad).unwrap());
        }

        for ct in &ciphertexts {
            let pt = s2.decrypt(ct, ad).unwrap();
            prop_assert!(msgs.contains(&pt.to_vec()), "Decrypted message must match one sent");
        }
    }

    #[test]
    fn prop_ratchet_serialize_deserialize_roundtrip(
        num_messages in 0..20usize,
    ) {
        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, Config::default(), HandshakeRole::Initiator
        ).unwrap();

        let ad = b"test_ad";
        for i in 0..num_messages {
            let _ = s1.encrypt(format!("msg_{}", i).as_bytes(), ad).unwrap();
        }

        let serialized = s1.serialize_state().unwrap();
        let s1_restored = DoubleRatchetSession::new(Config::default()).unwrap();
        s1_restored.deserialize_state(&serialized).unwrap();

        let ct = s1_restored.encrypt(b"after_restore", ad).unwrap();

        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, Config::default(), HandshakeRole::Responder
        ).unwrap();

        let pt = s2.decrypt(&ct, ad).unwrap();
        prop_assert_eq!(pt, b"after_restore");
    }

    #[test]
    fn prop_ratchet_skip_keys_bounds(
        num_skips in 0..3000usize,
    ) {
        use sibna_core::error::ProtocolError;

        let mut config = Config::default();
        config.max_skipped_messages = 100;

        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);

        let s1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1, pk2, config.clone(), HandshakeRole::Initiator
        ).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2, pk1, config.clone(), HandshakeRole::Responder
        ).unwrap();

        let ad = b"test_ad";
        for _ in 0..num_skips {
            let _ = s1.encrypt(b"skip", ad);
        }
        let ct = s1.encrypt(b"final", ad).unwrap();
        let result = s2.decrypt(&ct, ad);

        if num_skips > config.max_skipped_messages {
            prop_assert!(matches!(result, Err(ProtocolError::MaxSkippedMessagesExceeded)),
                "Excessive skips must be rejected");
        } else {
            prop_assert!(result.is_ok(), "Within bounds should succeed");
        }
    }
}