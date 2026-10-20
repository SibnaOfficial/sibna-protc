//! Integration tests for Sibna Protocol v3
//!
//! These tests verify end-to-end behaviour of the full protocol stack.
//! They are separate from unit tests to avoid coupling implementation details.

#![allow(warnings)]
use sibna_core::crypto::{CryptoHandler, KeyGenerator};
use sibna_core::ratchet::DoubleRatchetSession;
use sibna_core::*;
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

// ─────────────────────────────────────────────────────────────
// Context & identity
// ─────────────────────────────────────────────────────────────

#[test]
fn test_context_creation_with_password() {
    let config = Config::default();
    let result = SecureContext::new(config, Some(b"SecurePass1"));
    assert!(
        result.is_ok(),
        "Context creation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_context_creation_without_password() {
    let config = Config::default();
    let result = SecureContext::new(config, None);
    assert!(result.is_ok());
}

#[test]
fn test_weak_password_rejected() {
    let config = Config::default();
    // No uppercase
    assert!(SecureContext::new(config.clone(), Some(b"password1")).is_err());
    // No digit
    assert!(SecureContext::new(config.clone(), Some(b"Password")).is_err());
    // Too short
    assert!(SecureContext::new(config.clone(), Some(b"Ab1")).is_err());
    // Empty
    assert!(SecureContext::new(config, Some(b"")).is_err());
}

#[test]
fn test_identity_generation() {
    let config = Config::default();
    let ctx = SecureContext::new(config, Some(b"SecurePass1")).unwrap();
    let identity = ctx.generate_identity();
    assert!(identity.is_ok());
    let kp = identity.unwrap();
    // Public keys must not be zero
    assert!(!kp.ed25519_public.iter().all(|&b| b == 0));
    assert!(!kp.x25519_public.iter().all(|&b| b == 0));
}

#[test]
fn test_identity_key_validity() {
    let config = Config::default();
    let ctx = SecureContext::new(config, Some(b"SecurePass1")).unwrap();
    let kp = ctx.generate_identity().unwrap();
    assert!(kp.is_valid(), "Generated identity key must be valid");
}

// ─────────────────────────────────────────────────────────────
// Double Ratchet — core E2E encryption
// ─────────────────────────────────────────────────────────────

#[test]
fn test_double_ratchet_basic_encrypt_decrypt() {
    let config = Config::default();
    let shared_secret = [0x42u8; 32];

    let sk_alice = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_alice = PublicKey::from(&sk_alice);
    let sk_bob = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_alice,
        pk_bob,
        config.clone(),
        HandshakeRole::Initiator,
    )
    .unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_bob,
        pk_alice,
        config,
        HandshakeRole::Responder,
    )
    .unwrap();

    let plaintext = b"Hello Bob, this is Alice.";
    let ad = b"session-aad";

    let ciphertext = alice.encrypt(plaintext, ad).unwrap();
    let decrypted = bob.decrypt(&ciphertext, ad).unwrap();

    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_double_ratchet_multiple_messages() {
    let config = Config::default();
    let shared_secret = [0xABu8; 32];

    let sk_alice = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_alice = PublicKey::from(&sk_alice);
    let sk_bob = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_alice,
        pk_bob,
        config.clone(),
        HandshakeRole::Initiator,
    )
    .unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_bob,
        pk_alice,
        config,
        HandshakeRole::Responder,
    )
    .unwrap();

    for i in 0..50u32 {
        let msg = format!("message number {}", i);
        let ct = alice.encrypt(msg.as_bytes(), b"aad").unwrap();
        let pt = bob.decrypt(&ct, b"aad").unwrap();
        assert_eq!(msg.as_bytes(), pt.as_slice());
    }
}

#[test]
fn test_double_ratchet_replay_rejected() {
    let config = Config::default();
    let shared_secret = [0x11u8; 32];

    let sk_alice = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_alice = PublicKey::from(&sk_alice);
    let sk_bob = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_alice,
        pk_bob,
        config.clone(),
        HandshakeRole::Initiator,
    )
    .unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_bob,
        pk_alice,
        config,
        HandshakeRole::Responder,
    )
    .unwrap();

    let ct = alice.encrypt(b"test replay", b"aad").unwrap();
    let _ = bob.decrypt(&ct, b"aad").unwrap();

    // Second decrypt of same ciphertext must fail
    let replay = bob.decrypt(&ct, b"aad");
    assert!(replay.is_err(), "Replay attack must be detected");
}

#[test]
fn test_double_ratchet_wrong_ad_rejected() {
    let config = Config::default();
    let shared_secret = [0x22u8; 32];

    let sk_alice = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_alice = PublicKey::from(&sk_alice);
    let sk_bob = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_alice,
        pk_bob,
        config.clone(),
        HandshakeRole::Initiator,
    )
    .unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_bob,
        pk_alice,
        config,
        HandshakeRole::Responder,
    )
    .unwrap();

    let ct = alice.encrypt(b"secret", b"correct-aad").unwrap();
    let result = bob.decrypt(&ct, b"wrong-aad");
    assert!(result.is_err(), "Wrong AAD must be rejected");
}

#[test]
fn test_double_ratchet_tampered_ciphertext_rejected() {
    let config = Config::default();
    let shared_secret = [0x33u8; 32];

    let sk_alice = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_alice = PublicKey::from(&sk_alice);
    let sk_bob = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_alice,
        pk_bob,
        config.clone(),
        HandshakeRole::Initiator,
    )
    .unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        sk_bob,
        pk_alice,
        config,
        HandshakeRole::Responder,
    )
    .unwrap();

    let mut ct = alice.encrypt(b"tamper me", b"aad").unwrap();
    // Flip a byte in the ciphertext body (after header)
    let len = ct.len();
    ct[len / 2] ^= 0xFF;

    let result = bob.decrypt(&ct, b"aad");
    assert!(result.is_err(), "Tampered ciphertext must be rejected");
}

// ─────────────────────────────────────────────────────────────
// Crypto primitives
// ─────────────────────────────────────────────────────────────

#[test]
fn test_crypto_handler_roundtrip() {
    let key = KeyGenerator::generate_key().unwrap();
    let handler = CryptoHandler::new(key.as_ref()).unwrap();

    let plaintext = b"Integration test plaintext.";
    let ad = b"integration-test";

    let ct = handler.encrypt(plaintext, ad).unwrap();
    let pt = handler.decrypt(&ct, ad).unwrap();

    assert_eq!(plaintext.to_vec(), pt);
}

#[test]
fn test_crypto_handler_tamper_detection() {
    let key = KeyGenerator::generate_key().unwrap();
    let handler = CryptoHandler::new(key.as_ref()).unwrap();

    let mut ct = handler.encrypt(b"data", b"ad").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    assert!(handler.decrypt(&ct, b"ad").is_err());
}

#[test]
fn test_crypto_handler_key_isolation() {
    // Two different keys must not decrypt each other's output
    let k1 = KeyGenerator::generate_key().unwrap();
    let k2 = KeyGenerator::generate_key().unwrap();
    let h1 = CryptoHandler::new(k1.as_ref()).unwrap();
    let h2 = CryptoHandler::new(k2.as_ref()).unwrap();

    let ct = h1.encrypt(b"secret", b"").unwrap();
    assert!(h2.decrypt(&ct, b"").is_err());
}

#[test]
fn test_weak_key_rejected() {
    assert!(CryptoHandler::new(&[0u8; 32]).is_err());
    assert!(CryptoHandler::new(&[0xFFu8; 32]).is_err());
}

// ─────────────────────────────────────────────────────────────
// X3DH key agreement
// ─────────────────────────────────────────────────────────────

#[test]
fn test_x3dh_shared_secrets_match() {
    use sibna_core::handshake::x3dh::{verify_shared_secret, x3dh_initiator_v3, x3dh_responder_v3};

    let alice_identity = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let alice_ephemeral = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let alice_eph_pub = PublicKey::from(&alice_ephemeral);
    let alice_id_pub = PublicKey::from(&alice_identity);

    let bob_identity = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let bob_id_pub = PublicKey::from(&bob_identity);
    let bob_spk = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let bob_spk_pub = PublicKey::from(&bob_spk);
    let bob_opk = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let bob_opk_pub = PublicKey::from(&bob_opk);

    let result_alice = x3dh_initiator_v3(
        &alice_identity,
        &alice_ephemeral,
        &bob_id_pub,
        &bob_spk_pub,
        Some(&bob_opk_pub),
        None,
        &[0u8; 16],
        &[0u8; 16],
        &[0u8; 32],
    )
    .unwrap();

    let result_bob = x3dh_responder_v3(
        &bob_identity,
        &bob_spk,
        Some(&bob_opk),
        &alice_id_pub,
        &alice_eph_pub,
        None,
        None,
        &[0u8; 16],
        &[0u8; 16],
        &[0u8; 32],
    )
    .unwrap();

    assert!(
        verify_shared_secret(&result_alice, &result_bob),
        "X3DH: shared secrets must match between initiator and responder"
    );
}

#[test]
fn test_x3dh_without_onetime_prekey() {
    use sibna_core::handshake::x3dh::{verify_shared_secret, x3dh_initiator_v3, x3dh_responder_v3};

    let a_id = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let a_eph = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let a_id_pub = PublicKey::from(&a_id);
    let a_eph_pub = PublicKey::from(&a_eph);

    let b_id = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let b_id_pub = PublicKey::from(&b_id);
    let b_spk = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let b_spk_pub = PublicKey::from(&b_spk);

    let ra = x3dh_initiator_v3(
        &a_id, &a_eph, &b_id_pub, &b_spk_pub, None, None, &[0u8; 16], &[0u8; 16], &[0u8; 32],
    )
    .unwrap();
    let rb = x3dh_responder_v3(
        &b_id, &b_spk, None, &a_id_pub, &a_eph_pub, None, None, &[0u8; 16], &[0u8; 16], &[0u8; 32],
    )
    .unwrap();

    assert!(verify_shared_secret(&ra, &rb));
}

// ─────────────────────────────────────────────────────────────
// Safety numbers
// ─────────────────────────────────────────────────────────────

#[test]
fn test_safety_number_symmetry() {
    use sibna_core::safety::SafetyNumber;
    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    let sn_ab = SafetyNumber::calculate(&k1, &k2);
    let sn_ba = SafetyNumber::calculate(&k2, &k1);
    assert!(sn_ab.verify(&sn_ba), "Safety number must be symmetric");
}

#[test]
fn test_safety_number_different_keys() {
    use sibna_core::safety::SafetyNumber;
    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    let k3 = [0x33u8; 32];
    let sn1 = SafetyNumber::calculate(&k1, &k2);
    let sn2 = SafetyNumber::calculate(&k1, &k3);
    assert!(
        !sn1.verify(&sn2),
        "Different keys must produce different safety numbers"
    );
}

#[test]
fn test_safety_number_format() {
    use sibna_core::safety::SafetyNumber;
    let k1 = [0xAAu8; 32];
    let k2 = [0xBBu8; 32];
    let sn = SafetyNumber::calculate(&k1, &k2);
    let s = sn.as_string();
    let digits_only: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(
        digits_only.len(),
        80,
        "Safety number must have 80 decimal digits"
    );
}

// ─────────────────────────────────────────────────────────────
// Rate limiting
// ─────────────────────────────────────────────────────────────

#[test]
fn test_rate_limiter_allows_under_limit() {
    use sibna_core::rate_limit::RateLimiter;
    let limiter = RateLimiter::new();
    for _ in 0..5 {
        assert!(limiter.check("decrypt", "test_client").is_ok());
    }
}

#[test]
fn test_rate_limiter_blocks_over_limit() {
    use sibna_core::rate_limit::RateLimiter;
    let limiter = RateLimiter::new();
    // Exhaust decrypt per-second limit (5)
    for _ in 0..5 {
        let _ = limiter.check("decrypt", "client_x");
    }
    assert!(
        limiter.check("decrypt", "client_x").is_err(),
        "Rate limiter must block requests over limit"
    );
}

#[test]
fn test_rate_limiter_isolates_clients() {
    use sibna_core::rate_limit::RateLimiter;
    let limiter = RateLimiter::new();
    for _ in 0..5 {
        let _ = limiter.check("decrypt", "client_a");
    }
    // client_a is exhausted, client_b must still work
    assert!(
        limiter.check("decrypt", "client_b").is_ok(),
        "Rate limiter must isolate clients independently"
    );
}

// ─────────────────────────────────────────────────────────────
// Input validation
// ─────────────────────────────────────────────────────────────

#[test]
fn test_validate_message_empty_rejected() {
    use sibna_core::validation::validate_message;
    assert!(validate_message(b"").is_err());
}

#[test]
fn test_validate_message_valid() {
    use sibna_core::validation::validate_message;
    assert!(validate_message(b"hello world").is_ok());
}

#[test]
fn test_validate_key_weak_rejected() {
    use sibna_core::validation::validate_key;
    assert!(validate_key(&[0u8; 32]).is_err()); // all zeros
    assert!(validate_key(&[0xFFu8; 32]).is_err()); // all same
}

// ── P2P Transport ──

#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_p2p_local_connect_and_handshake() {
    use sibna_core::p2p::{P2pConfig, P2pNode};
    use sibna_core::{Config, SecureContext};

    // SIBNA-2026-037: P2P local connect now round-trips when both sides
    // pin `expected_peer_identity` (SIBNA-2026-020 enforcement).
    //
    // The transcript binding is sound (see `x3dh_initiator_v3` and
    // `x3dh_responder_v3` in `core/src/handshake/x3dh.rs`, plus the
    // P2P transcript in `core/src/p2p/handshake.rs::transcript_hash`).
    // The P2P Hello ephemeral is in the external binding; the X3DH
    // ephemeral is in the internal binding; HKDF-Extract(salt=external,
    // ikm=internal) cryptographically couples them. An attacker cannot
    // swap the X3DH envelope without also being able to substitute the
    // P2P Hello ephemeral, which is detected by the identity pin.
    //
    // The original (warn-only) path was the only path that round-tripped
    // before, but it left MITM protection disabled by default. This test
    // is the correct usage pattern: peers pre-exchange identities (e.g.,
    // via safety number QR code) and pin them before connecting.

    // Node A (Initiator)
    let ctx_a = SecureContext::new(Config::default(), None).unwrap();
    ctx_a.generate_identity().unwrap();
    let id_a = ctx_a.get_identity().unwrap().ed25519_public;

    // Node B (Responder) — generate FIRST so Alice can pin Bob's id.
    let ctx_b = SecureContext::new(Config::default(), None).unwrap();
    ctx_b.generate_identity().unwrap();
    let id_b = ctx_b.get_identity().unwrap().ed25519_public;

    let mut cfg_a = P2pConfig::default();
    cfg_a.expected_peer_identity = Some(id_b);
    let node_a =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_a, ctx_a)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };

    let mut cfg_b = P2pConfig::default();
    cfg_b.expected_peer_identity = Some(id_a);
    let node_b =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_b, ctx_b)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    let addr_b = node_b.local_addr();

    // Run connection asynchronously with a bounded timeout to prevent
    // hangs on platforms where mDNS or network discovery is unavailable.
    let b_task = tokio::spawn(async move { node_b.accept().await.unwrap() });

    let peer_a = match tokio::time::timeout(
        Duration::from_secs(30),
        node_a.connect(&format!("127.0.0.1:{}", addr_b.port())),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => panic!("P2P connect failed: {}", e),
        Err(_) => panic!("P2P connect timed out after 30 seconds"),
    };
    let peer_b = match tokio::time::timeout(Duration::from_secs(30), b_task).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => panic!("P2P accept task failed: {}", e),
        Err(_) => panic!("P2P accept task timed out after 30 seconds"),
    };

    // Send messages back and forth
    peer_a
        .send_message(b"hello from alice")
        .await
        .expect("Alice failed to send message");
    let msg1 = peer_b
        .recv_message()
        .await
        .expect("Bob failed to receive message");
    assert_eq!(msg1, b"hello from alice");

    peer_b
        .send_message(b"hi alice, this is bob")
        .await
        .expect("Bob failed to send message");
    let msg2 = peer_a
        .recv_message()
        .await
        .expect("Alice failed to receive message");
    assert_eq!(msg2, b"hi alice, this is bob");
}

#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_p2p_bundle_export_import() {
    use sibna_core::p2p::{P2pConfig, P2pNode};
    use sibna_core::{Config, SecureContext};

    let ctx = SecureContext::new(Config::default(), None).unwrap();
    ctx.generate_identity().unwrap();
    let node = match tokio::time::timeout(
        Duration::from_secs(30),
        P2pNode::new(P2pConfig::default(), ctx),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
        Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
    };

    let bytes = node.export_bundle();
    assert!(!bytes.is_empty());

    let bundle = P2pNode::import_bundle(&bytes).unwrap();
    assert_eq!(bundle.device_id, 0); // master device
}

#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_mdns_discovery() {
    use sibna_core::p2p::{P2pConfig, P2pNode};
    use sibna_core::{Config, SecureContext};
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    eprintln!("TEST: Starting mDNS discovery test");

    // Alice
    let ctx_a = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_a.generate_identity().unwrap();
    let mut cfg_a = P2pConfig::default();
    cfg_a.enable_mdns = true;
    cfg_a.node_name = Some("AliceDevice".to_string());
    // Binding to 0.0.0.0 is often more reliable for mDNS registration
    cfg_a.bind_addr = "0.0.0.0:0".parse().unwrap();

    eprintln!("TEST: Creating Alice node...");
    let node_a =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_a, ctx_a)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    eprintln!("TEST: Alice node created at {}", node_a.local_addr());

    // Give Alice's advertiser more time to fully register in the OS mDNS stack
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    eprintln!("TEST: Waited 2 seconds for Alice mDNS registration");

    // Bob
    let ctx_b = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_b.generate_identity().unwrap();
    let mut cfg_b = P2pConfig::default();
    cfg_b.enable_mdns = true;
    cfg_b.node_name = Some("BobDevice".to_string());
    cfg_b.bind_addr = "0.0.0.0:0".parse().unwrap();

    eprintln!("TEST: Creating Bob node...");
    let node_b =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_b, ctx_b)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    eprintln!("TEST: Bob node created at {}", node_b.local_addr());

    // Watch Bob's browser to discover Alice
    eprintln!("TEST: Starting peer browsing...");
    let mut browser = node_b.browse_peers().unwrap();
    eprintln!("TEST: Browser created, waiting for discovery...");

    let discovered = tokio::time::timeout(std::time::Duration::from_secs(10), browser.recv()).await;
    match &discovered {
        Ok(_) => eprintln!("TEST: Discovery succeeded within 10s"),
        Err(_) => eprintln!("TEST: Discovery timed out after 10s"),
    }
    let peer = discovered
        .expect("Timeout waiting for mDNS discovery")
        .expect("Channel closed");

    eprintln!("TEST: Discovered peer: {} at {}", peer.name, peer.addr);

    // Ensure we discovered Alice and the node name matches
    assert!(peer.name.contains("AliceDevice"));
    assert_eq!(peer.addr.port(), node_a.local_addr().port());

    eprintln!("TEST: Test passed! (test function will now return)");
}

/// Regression test: dropping the returned receiver while `P2pNode` remains alive
/// must not leave a blocking browse worker behind, and subsequent browse calls
/// on the same node must still work.
#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_mdns_browse_receiver_drop() {
    use sibna_core::p2p::{P2pConfig, P2pNode};
    use sibna_core::{Config, SecureContext};
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    eprintln!("TEST: Starting mDNS receiver-drop regression test");

    // Alice
    let ctx_a = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_a.generate_identity().unwrap();
    let mut cfg_a = P2pConfig::default();
    cfg_a.enable_mdns = true;
    cfg_a.node_name = Some("AliceDevice".to_string());
    cfg_a.bind_addr = "0.0.0.0:0".parse().unwrap();

    eprintln!("TEST: Creating Alice node...");
    let node_a =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_a, ctx_a)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    eprintln!("TEST: Alice node created at {}", node_a.local_addr());

    // Give Alice's advertiser time to register
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Bob
    let ctx_b = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_b.generate_identity().unwrap();
    let mut cfg_b = P2pConfig::default();
    cfg_b.enable_mdns = true;
    cfg_b.node_name = Some("BobDevice".to_string());
    cfg_b.bind_addr = "0.0.0.0:0".parse().unwrap();

    eprintln!("TEST: Creating Bob node...");
    let node_b =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_b, ctx_b)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    eprintln!("TEST: Bob node created at {}", node_b.local_addr());

    // Start browsing, then immediately drop the receiver while both nodes stay alive.
    // The browse worker must detect the closed channel and stop browsing.
    eprintln!("TEST: Starting peer browsing and dropping receiver...");
    let browser = node_b.browse_peers().unwrap();
    drop(browser);
    eprintln!("TEST: Receiver dropped while P2pNode still alive");

    // Give the background worker time to notice the closed channel and exit.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    eprintln!("TEST: First browse worker should have exited after receiver drop");

    // Start a NEW browse on the same node — it must still work, proving the
    // stale worker did not leave the mDNS daemon in a stopped state.
    eprintln!("TEST: Starting second browse after receiver drop...");
    let mut browser2 = node_b.browse_peers().unwrap();
    eprintln!("TEST: Second browse created, waiting for discovery...");

    let discovered =
        tokio::time::timeout(std::time::Duration::from_secs(10), browser2.recv()).await;
    match &discovered {
        Ok(_) => eprintln!("TEST: Second browse succeeded within 10s"),
        Err(_) => eprintln!("TEST: Second browse timed out after 10s"),
    }
    let peer = discovered
        .expect("Second browse timed out waiting for mDNS discovery")
        .expect("Second browse channel closed");

    eprintln!(
        "TEST: Second browse discovered peer: {} at {}",
        peer.name, peer.addr
    );

    // Ensure we discovered Alice and the node name matches
    assert!(
        peer.name.contains("AliceDevice"),
        "Second browse failed to discover AliceDevice after receiver drop"
    );
    assert_eq!(peer.addr.port(), node_a.local_addr().port());

    eprintln!("TEST: Receiver-drop regression test completed without hang");
}

/// Regression test: dropping `P2pNode` while discovery is active must stop the
/// browse worker and unregister the mDNS service cleanly, without hanging.
#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_mdns_node_drop_during_discovery() {
    use sibna_core::p2p::{P2pConfig, P2pNode};
    use sibna_core::{Config, SecureContext};
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    eprintln!("TEST: Starting mDNS node-drop regression test");

    // Alice
    let ctx_a = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_a.generate_identity().unwrap();
    let mut cfg_a = P2pConfig::default();
    cfg_a.enable_mdns = true;
    cfg_a.node_name = Some("AliceDevice".to_string());
    cfg_a.bind_addr = "0.0.0.0:0".parse().unwrap();

    eprintln!("TEST: Creating Alice node...");
    let node_a =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_a, ctx_a)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    eprintln!("TEST: Alice node created at {}", node_a.local_addr());

    // Give Alice's advertiser time to register
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Bob
    let ctx_b = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_b.generate_identity().unwrap();
    let mut cfg_b = P2pConfig::default();
    cfg_b.enable_mdns = true;
    cfg_b.node_name = Some("BobDevice".to_string());
    cfg_b.bind_addr = "0.0.0.0:0".parse().unwrap();

    eprintln!("TEST: Creating Bob node...");
    let node_b =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_b, ctx_b)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    eprintln!("TEST: Bob node created at {}", node_b.local_addr());

    // Start browsing, then drop Bob's node while discovery is active.
    // The `MdnsDiscovery::Drop` must stop browsing and unregister cleanly.
    eprintln!("TEST: Starting peer browsing...");
    let _browser = node_b.browse_peers().unwrap();
    eprintln!("TEST: Dropping Bob's P2pNode while discovery active...");
    drop(node_b);
    eprintln!("TEST: Bob's P2pNode dropped");

    // Give the background worker time to stop browsing and unregister.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    eprintln!("TEST: Node-drop regression test completed without hang");
}

/// Regression test: two concurrent `browse_peers()` calls on the same node
/// must both receive discovery events without one worker prematurely
/// stopping the other's browse via `stop_browse()`.
#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_mdns_concurrent_browse() {
    use sibna_core::p2p::{P2pConfig, P2pNode};
    use sibna_core::{Config, SecureContext};
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    eprintln!("TEST: Starting mDNS concurrent-browse regression test");

    // Alice
    let ctx_a = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_a.generate_identity().unwrap();
    let mut cfg_a = P2pConfig::default();
    cfg_a.enable_mdns = true;
    cfg_a.node_name = Some("AliceDevice".to_string());
    cfg_a.bind_addr = "0.0.0.0:0".parse().unwrap();

    eprintln!("TEST: Creating Alice node...");
    let node_a =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_a, ctx_a)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    eprintln!("TEST: Alice node created at {}", node_a.local_addr());

    // Give Alice's advertiser time to register
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Bob
    let ctx_b = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_b.generate_identity().unwrap();
    let mut cfg_b = P2pConfig::default();
    cfg_b.enable_mdns = true;
    cfg_b.node_name = Some("BobDevice".to_string());
    cfg_b.bind_addr = "0.0.0.0:0".parse().unwrap();

    eprintln!("TEST: Creating Bob node...");
    let node_b =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_b, ctx_b)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    eprintln!("TEST: Bob node created at {}", node_b.local_addr());

    // Start TWO concurrent browsers on Bob. Both must receive Alice's
    // discovery event without one worker stopping the other's browse.
    eprintln!("TEST: Starting two concurrent browsers...");
    let mut browser1 = node_b.browse_peers().unwrap();
    let mut browser2 = node_b.browse_peers().unwrap();
    eprintln!("TEST: Both browsers created");

    // Wait for either browser to discover Alice
    let discovered = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::select! {
            p = browser1.recv() => p,
            p = browser2.recv() => p,
        }
    })
    .await;
    let peer = discovered
        .expect("Concurrent browse timed out waiting for mDNS discovery")
        .expect("Concurrent browse channel closed");

    eprintln!(
        "TEST: Concurrent browse discovered peer: {} at {}",
        peer.name, peer.addr
    );

    assert!(
        peer.name.contains("AliceDevice"),
        "Concurrent browse failed to discover AliceDevice"
    );
    assert_eq!(peer.addr.port(), node_a.local_addr().port());

    // Drop both browsers; workers should exit cleanly without hang.
    drop(browser1);
    drop(browser2);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    eprintln!("TEST: Concurrent-browse regression test completed without hang");
}

#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_hybrid_routing_fallback() {
    use sibna_core::{Config, HybridRouter, P2pConfig, P2pNode, SecureContext};

    // Setup Alice
    let ctx_a = SecureContext::new(Config::default(), None).unwrap();
    ctx_a.generate_identity().unwrap();
    let id_a = ctx_a.get_identity().unwrap().ed25519_public;
    let mut router = HybridRouter::new(ctx_a.clone());

    // Setup Bob's ID
    let ctx_b = SecureContext::new(Config::default(), None).unwrap();
    let id_b = ctx_b.generate_identity().unwrap().ed25519_public;

    // 1. Send via Relay (Fallback) - should fail with SessionNotFound because no relay session exists
    // but this proves it reached the relay path.
    let res = router.send_message(&id_b, b"relay message").await;
    assert!(
        res.is_err(),
        "Expected SessionNotFound error for relay path without session"
    );

    // 2. Setup P2P and send via Direct
    // After SIBNA-2026-020 fix, P2P requires `expected_peer_identity` to be set.
    // Alice must know Bob's Ed25519 key out-of-band (e.g., via safety number exchange).
    // We forward-declare id_b_mock here so Alice's config can pin Bob's identity
    // *before* the mock node is created.
    let ctx_b_mock = SecureContext::new(Config::default(), None).unwrap();
    ctx_b_mock.generate_identity().unwrap();
    let id_b_mock = ctx_b_mock.get_identity().unwrap().ed25519_public;

    let mut cfg_a = P2pConfig::default();
    cfg_a.expected_peer_identity = Some(id_b_mock);
    let node_a =
        match tokio::time::timeout(Duration::from_secs(30), P2pNode::new(cfg_a, ctx_a)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
            Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
        };
    router.set_p2p_node(node_a);

    // We mock a P2P session by manually establishing one
    let mut cfg_b_mock = P2pConfig::default();
    cfg_b_mock.expected_peer_identity = Some(id_a);
    let node_b = match tokio::time::timeout(
        Duration::from_secs(30),
        P2pNode::new(cfg_b_mock, ctx_b_mock),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => panic!("P2PNode::new failed: {}", e),
        Err(_) => panic!("P2PNode::new timed out after 30 seconds"),
    };
    let addr_b = node_b.local_addr();

    // Note: Bob's P2P listener uses id_b_mock, NOT id_b. The earlier
    // id_b is used only for the relay-fallback test.

    // Start Bob's listener
    let _b_task = tokio::spawn(async move { node_b.accept().await.unwrap() });

    // Alice connects
    let p2p_node = router.p2p_node().expect("P2P node not set");
    let peer_for_alice = match tokio::time::timeout(
        Duration::from_secs(30),
        p2p_node.connect(&format!("127.0.0.1:{}", addr_b.port())),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => panic!("P2P connect failed: {}", e),
        Err(_) => panic!("P2P connect timed out after 30 seconds"),
    };
    let recipient_id = peer_for_alice.peer_id().to_vec();
    router.add_p2p_peer(peer_for_alice);

    // Now P2P should succeed!
    let res_p2p = router.send_message(&recipient_id, b"p2p message").await;
    assert!(res_p2p.is_ok(), "P2P delivery failed: {:?}", res_p2p.err());
}

// ─────────────────────────────────────────────────────────────
// Post-Quantum Cryptography (PQC)
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "pqc")]
#[tokio::test]
async fn test_p2p_pq_handshake_hybrid() {
    use sibna_core::p2p::{P2pConfig, P2pNode};

    // Initialize two PQC-enabled nodes
    let ctx_a = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_a.generate_identity().unwrap();
    let ctx_b = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_b.generate_identity().unwrap();

    let alice_id = ctx_a.get_identity().unwrap().ed25519_public;
    let bob_id = ctx_b.get_identity().unwrap().ed25519_public;

    // After SIBNA-2026-020 fix, P2P requires `expected_peer_identity`.
    let mut cfg_a = P2pConfig::default();
    cfg_a.expected_peer_identity = Some(bob_id);
    let mut cfg_b = P2pConfig::default();
    cfg_b.expected_peer_identity = Some(alice_id);

    let node_a = P2pNode::new(cfg_a, ctx_a).await.unwrap();
    let node_b = P2pNode::new(cfg_b, ctx_b).await.unwrap();

    let addr_b = node_b.local_addr();

    // Spawn responder
    let handle_b = tokio::spawn(async move { node_b.accept().await.unwrap() });

    // Initiator connects
    let peer_a = node_a
        .connect(&format!("127.0.0.1:{}", addr_b.port()))
        .await
        .expect("Alice failed to connect to Bob with PQC");
    let peer_b = handle_b.await.unwrap();

    // Verify both have sessions (Alice's peer ID should be Bob's identity key)
    assert_eq!(peer_a.peer_id(), &bob_id);

    // Send a message over the hybrid channel
    let msg = b"PQ-Safe message";
    peer_a.send_message(msg).await.unwrap();
    let received = peer_b.recv_message().await.unwrap();

    assert_eq!(msg.to_vec(), received);
}
