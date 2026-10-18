//! Cross-implementation Double Ratchet test: Rust ↔ Python.
//!
//! Order of execution:
//!   1. Python: write sibna_py_ratchet_ct.json (Python-encrypted ciphertexts)
//!   2. Rust:   read sibna_py_ratchet_ct.json, decrypt each ciphertext,
//!              write sibna_rust_ratchet_ct.json (Rust-encrypted ciphertexts)
//!   3. Python: read sibna_rust_ratchet_ct.json, decrypt each ciphertext

use sibna_core::ratchet::DoubleRatchetSession;
use sibna_core::{Config, HandshakeRole};
use x25519_dalek::{PublicKey, StaticSecret};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn hex_decode(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("invalid hex in test fixture")
}

fn get_temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(name)
}

fn py_ct_path() -> PathBuf {
    get_temp_path("sibna_py_ratchet_ct.json")
}

fn rust_ct_path() -> PathBuf {
    get_temp_path("sibna_rust_ratchet_ct.json")
}

fn alice_eph_secret() -> StaticSecret {
    StaticSecret::from([0x65u8; 32])
}

fn alice_eph_pub() -> PublicKey {
    PublicKey::from(&alice_eph_secret())
}

fn bob_spk_secret() -> StaticSecret {
    StaticSecret::from([0x63u8; 32])
}

fn bob_spk_pub() -> PublicKey {
    PublicKey::from(&bob_spk_secret())
}

#[test]
fn test_rust_decrypts_python_ciphertexts() {
    let py_path = py_ct_path();
    assert!(py_path.exists(), "Python ciphertext fixture missing at {}. Run the Python interop test first.", py_path.display());

    let content = fs::read_to_string(&py_path).expect("read py fixture");
    let data: Value = serde_json::from_str(&content).expect("parse py fixture");

    let shared_secret_hex = data["shared_secret"].as_str().expect("shared_secret missing");
    let shared_secret_vec = hex_decode(shared_secret_hex);
    let shared_secret: [u8; 32] = shared_secret_vec.try_into().expect("shared secret must be 32 bytes");
    
    let ciphertexts: Vec<&str> = data["ciphertexts"]
        .as_array()
        .expect("ciphertexts array missing")
        .iter()
        .map(|v| v.as_str().expect("ciphertext must be string"))
        .collect();
    
    let expected_plaintexts: Vec<&str> = data["expected_plaintexts"]
        .as_array()
        .expect("expected_plaintexts array missing")
        .iter()
        .map(|v| v.as_str().expect("plaintext must be string"))
        .collect();

    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        bob_spk_secret(),
        alice_eph_pub(),
        Config::default(),
        HandshakeRole::Responder,
    ).expect("create Bob session");

    for (ct_hex, expected_pt) in ciphertexts.iter().zip(expected_plaintexts.iter()) {
        let ct = hex_decode(ct_hex);
        let pt = bob.decrypt(&ct, b"ad").expect("Rust failed to decrypt Python ciphertext");
        assert_eq!(pt, expected_pt.as_bytes(), "Rust decryption mismatch for ciphertext {}", ct_hex);
    }
}

#[test]
fn test_rust_fails_on_tampered_python_ciphertext() {
    let py_path = py_ct_path();
    assert!(py_path.exists(), "Python ciphertext fixture missing");

    let content = fs::read_to_string(&py_path).expect("read py fixture");
    let data: Value = serde_json::from_str(&content).expect("parse py fixture");

    let shared_secret_hex = data["shared_secret"].as_str().expect("shared_secret missing");
    let shared_secret_vec = hex_decode(shared_secret_hex);
    let shared_secret: [u8; 32] = shared_secret_vec.try_into().expect("shared secret must be 32 bytes");
    
    let ct_hex = data["ciphertexts"][0].as_str().expect("ciphertext missing");
    let mut ct = hex_decode(ct_hex);
    
    // Tamper with the last byte of the ciphertext (authentication tag)
    let last_idx = ct.len() - 1;
    ct[last_idx] ^= 0xFF;

    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        bob_spk_secret(),
        alice_eph_pub(),
        Config::default(),
        HandshakeRole::Responder,
    ).expect("create Bob session");

    let result = bob.decrypt(&ct, b"ad");
    assert!(result.is_err(), "Rust should have failed to decrypt tampered ciphertext");
}

#[test]
fn test_rust_fails_on_wrong_ad() {
    let py_path = py_ct_path();
    assert!(py_path.exists(), "Python ciphertext fixture missing");

    let content = fs::read_to_string(&py_path).expect("read py fixture");
    let data: Value = serde_json::from_str(&content).expect("parse py fixture");

    let shared_secret_hex = data["shared_secret"].as_str().expect("shared_secret missing");
    let shared_secret_vec = hex_decode(shared_secret_hex);
    let shared_secret: [u8; 32] = shared_secret_vec.try_into().expect("shared secret must be 32 bytes");
    
    let ct_hex = data["ciphertexts"][0].as_str().expect("ciphertext missing");
    let ct = hex_decode(ct_hex);

    let bob = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        bob_spk_secret(),
        alice_eph_pub(),
        Config::default(),
        HandshakeRole::Responder,
    ).expect("create Bob session");

    let result = bob.decrypt(&ct, b"wrong_ad");
    assert!(result.is_err(), "Rust should have failed to decrypt with wrong associated data");
}

#[test]
fn test_rust_encrypts_writes_ciphertexts_for_python() {
    let py_path = py_ct_path();
    let shared_secret = if py_path.exists() {
        let content = fs::read_to_string(&py_path).unwrap();
        let data: Value = serde_json::from_str(&content).unwrap();
        let ss_vec = hex_decode(data["shared_secret"].as_str().unwrap());
        ss_vec.try_into().expect("shared secret must be 32 bytes")
    } else {
        let ss_vec = hex_decode("e03c8496aba67b549b979041d142e146e7b4a16acd72d11d068ab2c1a7a9c204");
        ss_vec.try_into().expect("shared secret must be 32 bytes")
    };

    let alice = DoubleRatchetSession::from_shared_secret(
        &shared_secret,
        alice_eph_secret(),
        bob_spk_pub(),
        Config::default(),
        HandshakeRole::Initiator,
    ).expect("create Alice session");

    let messages = vec!["Hi Alice #0", "Hi Alice #1", "Hi Alice #2"];
    let mut ciphertexts = Vec::new();

    for msg in &messages {
        let ct = alice.encrypt(msg.as_bytes(), b"ad").expect("Rust encrypt failed");
        ciphertexts.push(hex::encode(ct));
    }

    let output = serde_json::json!({
        "ciphertexts": ciphertexts,
        "expected_plaintexts": messages,
        "associated_data": "ad",
        "shared_secret": hex::encode(&shared_secret),
        "alice_ephemeral_public": hex::encode(alice_eph_pub().as_bytes()),
        "bob_signed_prekey_public": hex::encode(bob_spk_pub().as_bytes()),
    });

    fs::write(rust_ct_path(), serde_json::to_string_pretty(&output).unwrap())
        .expect("write rust ciphertexts");
}
