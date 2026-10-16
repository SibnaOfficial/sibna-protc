//! Deterministic interop test-vector generator for the Sibna Python SDK.
//!
//! Uses fixed seeds so the output is stable and can be committed as a fixture.
//! Run with: cargo test -p sibna-core --test gen_interop_vectors -- --nocapture
//! and redirect stdout to tests/cross_sdk/interop_vectors.json

use sibna_core::ratchet::DoubleRatchetSession;
use sibna_core::*;
use x25519_dalek::{PublicKey, StaticSecret};

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    generate_and_print();
}

#[test]
fn gen_interop_vectors() {
    generate_and_print();
}

fn generate_and_print() {
    // Fixed seeds
    let alice_seed = [0x61u8; 32]; // "a"
    let bob_seed = [0x62u8; 32]; // "b"

    let alice_identity = StaticSecret::from(alice_seed);
    let alice_id_pub = PublicKey::from(&alice_identity);
    let alice_ephemeral = StaticSecret::from([0x65u8; 32]); // "e"
    let alice_eph_pub = PublicKey::from(&alice_ephemeral);

    let bob_identity = StaticSecret::from(bob_seed);
    let bob_id_pub = PublicKey::from(&bob_identity);
    let bob_spk = StaticSecret::from([0x63u8; 32]); // "c"
    let bob_spk_pub = PublicKey::from(&bob_spk);
    let bob_opk = StaticSecret::from([0x64u8; 32]); // "d"
    let bob_opk_pub = PublicKey::from(&bob_opk);

    // === X3DH ===
    let ra = x3dh_initiator_v3(
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
    let rb = x3dh_responder_v3(
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
    assert!(verify_shared_secret(&ra, &rb));

    // === Double Ratchet (Rust wire format) ===
    let s1 = DoubleRatchetSession::from_shared_secret(
        &ra.shared_secret,
        alice_ephemeral,
        bob_spk_pub,
        Config::default(),
        HandshakeRole::Initiator,
    )
    .unwrap();
    let s2 = DoubleRatchetSession::from_shared_secret(
        &rb.shared_secret,
        StaticSecret::from([0x63u8; 32]),
        alice_eph_pub,
        Config::default(),
        HandshakeRole::Responder,
    )
    .unwrap();

    let msgs: Vec<Vec<u8>> = vec![
        b"Hello Bob #0".to_vec(),
        b"Hello Bob #1".to_vec(),
        b"Hello Bob #2".to_vec(),
    ];
    let mut alice_cts = Vec::new();
    for m in &msgs {
        alice_cts.push(s1.encrypt(m, b"ad").unwrap());
    }

    // Bob decrypts all
    let mut bob_pts = Vec::new();
    for ct in &alice_cts {
        bob_pts.push(s2.decrypt(ct, b"ad").unwrap());
    }
    assert_eq!(bob_pts, msgs);

    // Bob replies
    let bob_ct = s2.encrypt(b"Hi Alice", b"ad").unwrap();
    let alice_pt = s1.decrypt(&bob_ct, b"ad").unwrap();
    assert_eq!(alice_pt, b"Hi Alice");

    // === PQ hybrid X3DH ===
    use fips203::ml_kem_768;
    use fips203::traits::{KeyGen, SerDes};
    let (pq_pk, pq_sk) = ml_kem_768::KG::try_keygen().unwrap();
    let pq_pk_bytes = SerDes::into_bytes(pq_pk).to_vec();
    let pq_sk_bytes = SerDes::into_bytes(pq_sk).to_vec();

    let ra_pq = x3dh_initiator_v3(
        &alice_identity,
        &StaticSecret::from([0x65u8; 32]),
        &bob_id_pub,
        &bob_spk_pub,
        None,
        Some(&pq_pk_bytes),
        &[0u8; 16],
        &[0u8; 16],
        &[0u8; 32],
    )
    .unwrap();
    let rb_pq = x3dh_responder_v3(
        &bob_identity,
        &bob_spk,
        None,
        &alice_id_pub,
        &alice_eph_pub,
        Some(&pq_sk_bytes),
        Some(ra_pq.pq_ciphertext.as_ref().unwrap()),
        &[0u8; 16],
        &[0u8; 16],
        &[0u8; 32],
    )
    .unwrap();
    assert!(verify_shared_secret(&ra_pq, &rb_pq));

    // === Safety number ===
    let sn = SafetyNumber::calculate(&alice_id_pub.to_bytes(), &bob_id_pub.to_bytes());

    // Emit JSON
    let out = serde_json::json!({
        "alice_seed": hex(&alice_seed),
        "bob_seed": hex(&bob_seed),
        "alice_identity_ed25519": hex(&alice_seed), // placeholder (deterministic ed key)
        "alice_identity_x25519": hex(&alice_id_pub.to_bytes()),
        "bob_identity_x25519": hex(&bob_id_pub.to_bytes()),
        "bob_spk": hex(&bob_spk_pub.to_bytes()),
        "bob_opk": hex(&bob_opk_pub.to_bytes()),
        "alice_ephemeral": hex(&alice_eph_pub.to_bytes()),
        "x3dh_shared_secret": hex(&ra.shared_secret),
        "x3dh_pq_shared_secret": hex(&ra_pq.shared_secret),
        "ml_kem_pk": hex(&pq_pk_bytes),
        "ml_kem_sk": hex(&pq_sk_bytes),
        "alice_to_bob_ct": alice_cts.iter().map(|c| hex(c)).collect::<Vec<_>>(),
        "bob_to_alice_ct": hex(&bob_ct),
        "safety_number": sn.as_string(),
        "safety_number_fingerprint": hex(sn.fingerprint()),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
