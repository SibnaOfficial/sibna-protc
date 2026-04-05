//! Integration tests for Sibna Protocol v9
//!
//! These tests verify end-to-end behaviour of the full protocol stack.
//! They are separate from unit tests to avoid coupling implementation details.

#![allow(warnings)]
use sibna_core::*;
use sibna_core::crypto::{CryptoHandler, KeyGenerator};
use sibna_core::ratchet::DoubleRatchetSession;
use x25519_dalek::{StaticSecret, PublicKey};

// ─────────────────────────────────────────────────────────────
// Context & identity
// ─────────────────────────────────────────────────────────────

#[test]
fn test_context_creation_with_password() {
    let config = Config::default();
    let result = SecureContext::new(config, Some(b"SecurePass1"));
    assert!(result.is_ok(), "Context creation failed: {:?}", result.err());
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
    let sk_bob   = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob   = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_alice, pk_bob, config.clone(), true
    ).unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_bob, pk_alice, config, false
    ).unwrap();

    let plaintext = b"Hello Bob, this is Alice.";
    let ad = b"session-aad";

    let ciphertext = alice.encrypt(plaintext, ad).unwrap();
    let decrypted  = bob.decrypt(&ciphertext, ad).unwrap();

    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_double_ratchet_multiple_messages() {
    let config = Config::default();
    let shared_secret = [0xABu8; 32];

    let sk_alice = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_alice = PublicKey::from(&sk_alice);
    let sk_bob   = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob   = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_alice, pk_bob, config.clone(), true
    ).unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_bob, pk_alice, config, false
    ).unwrap();

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
    let sk_bob   = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob   = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_alice, pk_bob, config.clone(), true
    ).unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_bob, pk_alice, config, false
    ).unwrap();

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
    let sk_bob   = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob   = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_alice, pk_bob, config.clone(), true
    ).unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_bob, pk_alice, config, false
    ).unwrap();

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
    let sk_bob   = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let pk_bob   = PublicKey::from(&sk_bob);

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_alice, pk_bob, config.clone(), true
    ).unwrap();
    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret, sk_bob, pk_alice, config, false
    ).unwrap();

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
    use sibna_core::handshake::x3dh::{x3dh_initiator, x3dh_responder, verify_shared_secret};

    let alice_identity  = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let alice_ephemeral = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let alice_eph_pub   = PublicKey::from(&alice_ephemeral);
    let alice_id_pub    = PublicKey::from(&alice_identity);

    let bob_identity   = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let bob_id_pub     = PublicKey::from(&bob_identity);
    let bob_spk        = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let bob_spk_pub    = PublicKey::from(&bob_spk);
    let bob_opk        = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let bob_opk_pub    = PublicKey::from(&bob_opk);

    let result_alice = x3dh_initiator(
        &alice_identity, &alice_ephemeral,
        &bob_id_pub, &bob_spk_pub, Some(&bob_opk_pub),
        None,
    ).unwrap();

    let result_bob = x3dh_responder(
        &bob_identity, &bob_spk, Some(&bob_opk),
        &alice_id_pub, &alice_eph_pub,
        None, None,
    ).unwrap();

    assert!(verify_shared_secret(&result_alice, &result_bob),
        "X3DH: shared secrets must match between initiator and responder");
}

#[test]
fn test_x3dh_without_onetime_prekey() {
    use sibna_core::handshake::x3dh::{x3dh_initiator, x3dh_responder, verify_shared_secret};

    let a_id  = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let a_eph = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let a_id_pub  = PublicKey::from(&a_id);
    let a_eph_pub = PublicKey::from(&a_eph);

    let b_id  = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let b_id_pub = PublicKey::from(&b_id);
    let b_spk = StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let b_spk_pub = PublicKey::from(&b_spk);

    let ra = x3dh_initiator(&a_id, &a_eph, &b_id_pub, &b_spk_pub, None, None).unwrap();
    let rb = x3dh_responder(&b_id, &b_spk, None, &a_id_pub, &a_eph_pub, None, None).unwrap();

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
    assert!(!sn1.verify(&sn2), "Different keys must produce different safety numbers");
}

#[test]
fn test_safety_number_format() {
    use sibna_core::safety::SafetyNumber;
    let k1 = [0xAAu8; 32];
    let k2 = [0xBBu8; 32];
    let sn = SafetyNumber::calculate(&k1, &k2);
    let s = sn.as_string();
    let digits_only: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(digits_only.len(), 80, "Safety number must have 80 decimal digits");
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
    assert!(limiter.check("decrypt", "client_x").is_err(),
        "Rate limiter must block requests over limit");
}

#[test]
fn test_rate_limiter_isolates_clients() {
    use sibna_core::rate_limit::RateLimiter;
    let limiter = RateLimiter::new();
    for _ in 0..5 {
        let _ = limiter.check("decrypt", "client_a");
    }
    // client_a is exhausted, client_b must still work
    assert!(limiter.check("decrypt", "client_b").is_ok(),
        "Rate limiter must isolate clients independently");
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
    assert!(validate_key(&[0u8; 32]).is_err());   // all zeros
    assert!(validate_key(&[0xFFu8; 32]).is_err()); // all same
}

// ── P2P Transport ──

#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_p2p_local_connect_and_handshake() {
    use sibna_core::p2p::{P2pNode, P2pConfig};
    use sibna_core::{SecureContext, Config};

    // Node A (Initiator)
    let ctx_a = SecureContext::new(Config::default(), None).unwrap();
    ctx_a.generate_identity().unwrap();
    let node_a = P2pNode::new(P2pConfig::default(), ctx_a).await.unwrap();

    // Node B (Responder)
    let ctx_b = SecureContext::new(Config::default(), None).unwrap();
    ctx_b.generate_identity().unwrap();
    let node_b = P2pNode::new(P2pConfig::default(), ctx_b).await.unwrap();
    let addr_b = node_b.local_addr();

    // Run connection asynchronously
    let b_task = tokio::spawn(async move {
        node_b.accept().await.unwrap()
    });

    let peer_a = node_a.connect(&format!("127.0.0.1:{}", addr_b.port())).await.unwrap();
    let peer_b = b_task.await.unwrap();

    // Send messages back and forth
    peer_a.send_message(b"hello from alice").await.unwrap();
    let msg1 = peer_b.recv_message().await.unwrap();
    assert_eq!(msg1, b"hello from alice");

    peer_b.send_message(b"hi alice, this is bob").await.unwrap();
    let msg2 = peer_a.recv_message().await.unwrap();
    assert_eq!(msg2, b"hi alice, this is bob");
}

#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_p2p_bundle_export_import() {
    use sibna_core::p2p::{P2pNode, P2pConfig};
    use sibna_core::{SecureContext, Config};

    let ctx = SecureContext::new(Config::default(), None).unwrap();
    ctx.generate_identity().unwrap();
    let node = P2pNode::new(P2pConfig::default(), ctx).await.unwrap();

    let bytes = node.export_bundle();
    assert!(!bytes.is_empty());

    let bundle = P2pNode::import_bundle(&bytes).unwrap();
    assert_eq!(bundle.device_id, 0); // master device
}

#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_mdns_discovery() {
    use sibna_core::p2p::{P2pNode, P2pConfig};
    use sibna_core::{SecureContext, Config};
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    // Alice
    let ctx_a = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_a.generate_identity().unwrap();
    let mut cfg_a = P2pConfig::default();
    cfg_a.enable_mdns = true;
    cfg_a.node_name = Some("AliceDevice".to_string());
    // Binding to 0.0.0.0 is often more reliable for mDNS registration
    cfg_a.bind_addr = "0.0.0.0:0".parse().unwrap();

    let node_a = P2pNode::new(cfg_a, ctx_a).await.unwrap();

    // Give Alice's advertiser more time to fully register in the OS mDNS stack
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Bob
    let ctx_b = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_b.generate_identity().unwrap();
    let mut cfg_b = P2pConfig::default();
    cfg_b.enable_mdns = true;
    cfg_b.node_name = Some("BobDevice".to_string());
    cfg_b.bind_addr = "0.0.0.0:0".parse().unwrap();

    let node_b = P2pNode::new(cfg_b, ctx_b).await.unwrap();

    // Watch Bob's browser to discover Alice
    let mut browser = node_b.browse_peers().unwrap();

    let discovered = tokio::time::timeout(std::time::Duration::from_secs(10), browser.recv()).await;
    let peer = discovered.expect("Timeout waiting for mDNS discovery").expect("Channel closed");

    // Ensure we discovered Alice and the node name matches
    assert!(peer.name.contains("AliceDevice"));
    assert_eq!(peer.addr.port(), node_a.local_addr().port());
}

#[cfg(feature = "p2p")]
#[tokio::test]
async fn test_hybrid_routing_fallback() {
    use sibna_core::{HybridRouter, SecureContext, Config, P2pNode, P2pConfig};
    
    // Setup Alice
    let ctx_a = SecureContext::new(Config::default(), None).unwrap();
    ctx_a.generate_identity().unwrap();
    let mut router = HybridRouter::new(ctx_a.clone());

    // Setup Bob's ID
    let ctx_b = SecureContext::new(Config::default(), None).unwrap();
    let id_b = ctx_b.generate_identity().unwrap().ed25519_public;

    // 1. Send via Relay (Fallback) - should fail with SessionNotFound because no relay session exists
    // but this proves it reached the relay path.
    let res = router.send_message(&id_b, b"relay message").await;
    assert!(res.is_err(), "Expected SessionNotFound error for relay path without session");

    // 2. Setup P2P and send via Direct
    let node_a = P2pNode::new(P2pConfig::default(), ctx_a).await.unwrap();
    router.set_p2p_node(node_a);
    
    // We mock a P2P session by manually establishing one
    let ctx_b_mock = SecureContext::new(Config::default(), None).unwrap();
    ctx_b_mock.generate_identity().unwrap();
    let node_b = P2pNode::new(P2pConfig::default(), ctx_b_mock).await.unwrap();
    let addr_b = node_b.local_addr();

    // Start Bob's listener
    let _b_task = tokio::spawn(async move {
        node_b.accept().await.unwrap()
    });

    // Alice connects
    let p2p_node = router.p2p_node().expect("P2P node not set");
    let peer_for_alice = p2p_node.connect(&format!("127.0.0.1:{}", addr_b.port())).await.unwrap();
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
    use sibna_core::p2p::{P2pNode, P2pConfig};

    // Initialize two PQC-enabled nodes
    let ctx_a = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_a.generate_identity().unwrap();
    let ctx_b = SecureContext::new(Config::default(), Some(b"SecurePass1")).unwrap();
    ctx_b.generate_identity().unwrap();

    let _alice_id = ctx_a.get_identity().unwrap().ed25519_public;
    let bob_id = ctx_b.get_identity().unwrap().ed25519_public;

    let node_a = P2pNode::new(P2pConfig::default(), ctx_a).await.unwrap();
    let node_b = P2pNode::new(P2pConfig::default(), ctx_b).await.unwrap();

    let addr_b = node_b.local_addr();

    // Spawn responder
    let handle_b = tokio::spawn(async move {
        node_b.accept().await.unwrap()
    });

    // Initiator connects
    let peer_a = node_a.connect(&format!("127.0.0.1:{}", addr_b.port())).await.expect("Alice failed to connect to Bob with PQC");
    let peer_b = handle_b.await.unwrap();

    // Verify both have sessions (Alice's peer ID should be Bob's identity key)
    assert_eq!(peer_a.peer_id(), &bob_id);

    // Send a message over the hybrid channel
    let msg = b"PQ-Safe message";
    peer_a.send_message(msg).await.unwrap();
    let received = peer_b.recv_message().await.unwrap();

    assert_eq!(msg.to_vec(), received);
}
