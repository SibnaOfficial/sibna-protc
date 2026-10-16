//! Test-only example harness: ML-KEM-768 + hybrid X3DH cross-implementation vectors.
//
// NOT production code. Lives under examples/ so it can define `main()` and be
// invoked by the Python conformance test as a subprocess via `cargo run --example`.
//
// Subcommands:
//   generate        print JSON vectors to stdout.
//   decapsulate <sk_hex> <ct_hex>  -> print shared_secret_hex to stdout.
//   x3dh_respond      -> read JSON from stdin, run the Rust X3DH responder with
//                        PQ, print shared_secret_hex to stdout.
//
// Uses FIPS 203 encodings exactly as the production handshake
// (core/src/handshake/x3dh.rs, core/src/crypto/kdf.rs::derive_pq_shared_secret):
//   pk: 1184 bytes, sk: 2400 bytes, ct: 1088 bytes, ss: 32 bytes.
// Hybrid derivation: HKDF(salt=combined_transcript, ikm=dh1||dh2||dh3||dh4||ss_kem,
//                          info="SibnaPQX3DH_v3", length=32).

#![allow(missing_docs)]

use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use serde::Serialize;
use sibna_core::error::{ProtocolError, ProtocolResult};
use sibna_core::handshake::x3dh::{
    x3dh_initiator_v3, x3dh_responder_v3,
};
use x25519_dalek::{PublicKey, StaticSecret};
use blake3::Hasher;
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Serialize)]
struct KemVectors {
    algorithm: String,
    pk_len: usize,
    sk_len: usize,
    ct_len: usize,
    ss_len: usize,
}

#[derive(Serialize)]
struct GenerateOutput {
    kem: KemVectors,
    // Direction A: Rust encapsulates pk_a -> (ct_a, ss_a). Python decapsulates ct_a with sk_a.
    pk_a_hex: String,
    sk_a_hex: String,
    ct_a_hex: String,
    ss_a_hex: String,
    // Direction B: pk_b / sk_b for Python to encapsulate and Rust to decapsulate.
    pk_b_hex: String,
    sk_b_hex: String,
    // Hybrid handshake: Rust initiator (Alice) -> Python responder (Bob).
    // Alice uses pk_b as peer_pq_pk, producing pq_ct_to_b and shared_secret_alice.
    alice_identity_hex: String,
    alice_ephemeral_hex: String,
    alice_pq_ct_to_b_hex: String,
    alice_shared_secret_hex: String,
    bob_identity_pk_hex: String,
    bob_spk_pk_hex: String,
    bob_device_id_hex: String,
    alice_device_id_hex: String,
    transcript_ext_hex: String,
}

fn fixed_seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect()
}

fn decode_hex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn static_secret_from_hex(h: &str) -> StaticSecret {
    let bytes: [u8; 32] = decode_hex(h).try_into().expect("32-byte seed");
    StaticSecret::from(bytes)
}

fn public_key_from_hex(h: &str) -> PublicKey {
    let bytes: [u8; 32] = decode_hex(h).as_slice().try_into().expect("32-byte public key");
    PublicKey::from(bytes)
}

fn generate_vectors() -> ProtocolResult<GenerateOutput> {
    let kem = KemVectors {
        algorithm: "ml-kem-768".to_string(),
        pk_len: 1184,
        sk_len: 2400,
        ct_len: 1088,
        ss_len: 32,
    };

    // ---- Key pairs (A and B) ----
    let (pk_a, sk_a) = ml_kem_768::KG::try_keygen().expect("ML-KEM keypair A");
    let pk_a_bytes = SerDes::into_bytes(pk_a).to_vec();
    let sk_a_bytes = SerDes::into_bytes(sk_a).to_vec();

    let (pk_b, sk_b) = ml_kem_768::KG::try_keygen().expect("ML-KEM keypair B");
    let pk_b_bytes = SerDes::into_bytes(pk_b).to_vec();
    let sk_b_bytes = SerDes::into_bytes(sk_b).to_vec();

    // ---- Direction A: Rust encapsulates pk_a -> (ct_a, ss_a) ----
    let pk_a_encap_key = ml_kem_768::EncapsKey::try_from_bytes(
        pk_a_bytes.as_slice().try_into().expect("1184-byte pk"),
    )
    .expect("valid ML-KEM-768 public key");
    let (ss_a, ct_a) =
        <ml_kem_768::EncapsKey as Encaps>::try_encaps(&pk_a_encap_key).expect("encapsulate");
    let ss_a_bytes = SerDes::into_bytes(ss_a);
    let ct_a_bytes = SerDes::into_bytes(ct_a).to_vec();

    // ---- Sanity: Rust decapsulates its own ciphertext (internal consistency) ----
    let sk_a_dec_key = ml_kem_768::DecapsKey::try_from_bytes(
        sk_a_bytes.as_slice().try_into().expect("2400-byte sk"),
    )
    .expect("valid ML-KEM-768 secret key");
    let ct_a_cipher = ml_kem_768::CipherText::try_from_bytes(
        ct_a_bytes.as_slice().try_into().expect("1088-byte ct"),
    )
    .expect("valid ML-KEM-768 ciphertext");
    let ss_a_check =
        <ml_kem_768::DecapsKey as Decaps>::try_decaps(&sk_a_dec_key, &ct_a_cipher)
            .expect("ML-KEM-768 decapsulate");
    assert_eq!(
        SerDes::into_bytes(ss_a_check),
        ss_a_bytes,
        "Rust self-decapsulation mismatch"
    );

    // ---- Hybrid handshake: Rust initiator (Alice) -> Python responder (Bob) ----
    let alice_identity = static_secret_from_hex(&hex(&fixed_seed(0x61)));
    let alice_identity_pk = PublicKey::from(&alice_identity);
    let alice_ephemeral = static_secret_from_hex(&hex(&fixed_seed(0x65)));
    let alice_ephemeral_pk = PublicKey::from(&alice_ephemeral);

    let bob_identity = static_secret_from_hex(&hex(&fixed_seed(0x62)));
    let bob_identity_pk = PublicKey::from(&bob_identity);
    let bob_spk = static_secret_from_hex(&hex(&fixed_seed(0x63)));
    let bob_spk_pk = PublicKey::from(&bob_spk);

    let alice_device_id = [0u8; 16];
    let bob_device_id = [0u8; 16];
    let transcript_ext = [0u8; 32];

    let pk_b_vec: Vec<u8> = pk_b_bytes.clone();
    let alice_result = x3dh_initiator_v3(
        &alice_identity,
        &alice_ephemeral,
        &bob_identity_pk,
        &bob_spk_pk,
        None, // no one-time prekey
        Some(&pk_b_vec),
        &alice_device_id,
        &bob_device_id,
        &transcript_ext,
    )
    .expect("Rust X3DH initiator with PQ");
    assert!(alice_result.pq_ciphertext.is_some());
    let alice_pq_ct_to_b = alice_result
        .pq_ciphertext
        .clone()
        .expect("pq ciphertext present");

    Ok(GenerateOutput {
        kem,
        pk_a_hex: hex(&pk_a_bytes),
        sk_a_hex: hex(&sk_a_bytes),
        ct_a_hex: hex(&ct_a_bytes),
        ss_a_hex: hex(&ss_a_bytes),
        pk_b_hex: hex(&pk_b_bytes),
        sk_b_hex: hex(&sk_b_bytes),
        alice_identity_hex: hex(alice_identity_pk.as_bytes()),
        alice_ephemeral_hex: hex(alice_ephemeral_pk.as_bytes()),
        alice_pq_ct_to_b_hex: hex(&alice_pq_ct_to_b),
        alice_shared_secret_hex: hex(alice_result.shared_secret.as_ref()),
        bob_identity_pk_hex: hex(bob_identity_pk.as_bytes()),
        bob_spk_pk_hex: hex(bob_spk_pk.as_bytes()),
        bob_device_id_hex: hex(&bob_device_id),
        alice_device_id_hex: hex(&alice_device_id),
        transcript_ext_hex: hex(&transcript_ext),
    })
}

#[derive(Serialize)]
struct RespondOutput {
    shared_secret_hex: String,
}

// "x3dh_respond" mode: Rust acts as the responder (Bob) to a Python initiator.
// Reads JSON from stdin with all responder inputs, including the PQ ciphertext
// produced by Python's encapsulation and Bob's ML-KEM secret key.
fn x3dh_respond(stdin: &[u8]) -> ProtocolResult<RespondOutput> {
    let input: serde_json::Value = serde_json::from_slice(stdin)
        .map_err(|_| ProtocolError::InvalidArgument)?;

    let bob_identity = static_secret_from_hex(
        input["bob_identity_hex"]
            .as_str()
            .ok_or(ProtocolError::InvalidArgument)?,
    );
    let bob_spk = static_secret_from_hex(
        input["bob_spk_hex"]
            .as_str()
            .ok_or(ProtocolError::InvalidArgument)?,
    );
    let alice_identity_pk = public_key_from_hex(
        input["alice_identity_pk_hex"]
            .as_str()
            .ok_or(ProtocolError::InvalidArgument)?,
    );
    let alice_ephemeral_pk = public_key_from_hex(
        input["alice_ephemeral_pk_hex"]
            .as_str()
            .ok_or(ProtocolError::InvalidArgument)?,
    );
    let our_pq_sk_hex = input["our_pq_sk_hex"]
        .as_str()
        .ok_or(ProtocolError::InvalidArgument)?;
    let peer_pq_ct_hex = input["peer_pq_ct_hex"]
        .as_str()
        .ok_or(ProtocolError::InvalidArgument)?;
    let our_device_id_hex = input["our_device_id_hex"]
        .as_str()
        .ok_or(ProtocolError::InvalidArgument)?;
    let peer_device_id_hex = input["peer_device_id_hex"]
        .as_str()
        .ok_or(ProtocolError::InvalidArgument)?;
    let transcript_ext_hex = input["transcript_ext_hex"]
        .as_str()
        .ok_or(ProtocolError::InvalidArgument)?;

    let our_pq_sk_bytes = decode_hex(our_pq_sk_hex);
    let peer_pq_ct_bytes = decode_hex(peer_pq_ct_hex);
    let our_device_id: [u8; 16] = decode_hex(our_device_id_hex)
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::InvalidArgument)?;
    let peer_device_id: [u8; 16] = decode_hex(peer_device_id_hex)
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::InvalidArgument)?;
    let transcript_ext: [u8; 32] = decode_hex(transcript_ext_hex)
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::InvalidArgument)?;

    // Debug: replicate the responder's internal DH + transcript construction
    // so we can compare against the Python initiator side.
    let dh1 = bob_spk.diffie_hellman(&alice_identity_pk);
    let dh2 = bob_identity.diffie_hellman(&alice_ephemeral_pk);
    let dh3 = bob_spk.diffie_hellman(&alice_ephemeral_pk);
    let mut hasher = Hasher::new();
    hasher.update(alice_identity_pk.as_bytes());
    hasher.update(alice_ephemeral_pk.as_bytes());
    hasher.update(PublicKey::from(&bob_identity).as_bytes());
    hasher.update(PublicKey::from(&bob_spk).as_bytes());
    hasher.update(&peer_device_id);
    hasher.update(&our_device_id);
    let transcript_hash: [u8; 32] = hasher.finalize().into();
    let mut combined_transcript = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(transcript_ext.as_slice()), transcript_hash.as_slice());
    hk.expand(b"SibnaX3DH_TranscriptBind_v3", &mut combined_transcript[..])
        .expect("HKDF expand");

    eprintln!("DEBUG responder dh1={} dh2={} dh3={}", hex(dh1.as_bytes()), hex(dh2.as_bytes()), hex(dh3.as_bytes()));
    eprintln!("DEBUG responder transcript={}", hex(transcript_hash.as_slice()));
    eprintln!("DEBUG responder combined={}", hex(&combined_transcript));
    eprintln!("DEBUG responder our_pq_sk={}", our_pq_sk_hex);
    eprintln!("DEBUG responder peer_pq_ct={}", peer_pq_ct_hex);

    let bob_result = x3dh_responder_v3(
        &bob_identity,
        &bob_spk,
        None, // no one-time prekey
        &alice_identity_pk,
        &alice_ephemeral_pk,
        Some(&our_pq_sk_bytes),
        Some(&peer_pq_ct_bytes),
        &our_device_id,
        &peer_device_id,
        &transcript_ext,
    )
    .expect("Rust X3DH responder with PQ");

    eprintln!("DEBUG responder shared_secret={}", hex(bob_result.shared_secret.as_ref()));

    Ok(RespondOutput {
        shared_secret_hex: hex(bob_result.shared_secret.as_ref()),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("generate") => {
            let out = generate_vectors().expect("generate vectors");
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Some("decapsulate") => {
            let sk_hex = args.get(1).map(|_| &args[2]).expect("usage: decapsulate <sk_hex> <ct_hex>");
            let ct_hex = args.get(3).expect("usage: decapsulate <sk_hex> <ct_hex>");
            let sk_bytes = decode_hex(sk_hex);
            let ct_bytes = decode_hex(ct_hex);
            let sk_key = ml_kem_768::DecapsKey::try_from_bytes(
                sk_bytes.as_slice().try_into().map_err(|_| ()).unwrap(),
            )
            .unwrap();
            let ct_cipher = ml_kem_768::CipherText::try_from_bytes(
                ct_bytes.as_slice().try_into().unwrap(),
            )
            .unwrap();
            let ss = <ml_kem_768::DecapsKey as Decaps>::try_decaps(&sk_key, &ct_cipher).unwrap();
            print!("{}", hex(&SerDes::into_bytes(ss)));
        }
        Some("x3dh_respond") => {
            let mut stdin = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut stdin).expect("read stdin");
            let out = x3dh_respond(&stdin).expect("x3dh respond");
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        _ => {
            eprintln!(
                "usage: pq_kem_x3dh_interop {{generate|decapsulate <sk> <ct>|x3dh_respond}}"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use sibna_core::handshake::x3dh::verify_shared_secret;

    use super::*;

    #[test]
    fn generate_vectors_is_consistent() {
        let out = generate_vectors().unwrap();
        assert_eq!(out.kem.pk_len, 1184);
        assert_eq!(out.kem.sk_len, 2400);
        assert_eq!(out.kem.ct_len, 1088);
        assert_eq!(out.kem.ss_len, 32);
        assert_eq!(out.pk_a_hex.len(), 2368);
        assert_eq!(out.sk_a_hex.len(), 4800);
        assert_eq!(out.ct_a_hex.len(), 2176);
        assert_eq!(out.ss_a_hex.len(), 64);
        assert_ne!(out.alice_shared_secret_hex, "0".repeat(64));
        // Rust decapsulates its own ciphertext (already asserted inside generate_vectors);
        // here we also confirm Python-readable sizes.
        assert!(out.ct_a_hex.len() > 0);
    }

    #[test]
    fn x3dh_respond_matches_generate() {
        let gen = generate_vectors().unwrap();
        // Rust initiator -> Rust responder control test using Bob's fixed secret keys.
        let input = serde_json::json!({
            "bob_identity_hex": hex(&fixed_seed(0x62)),
            "bob_spk_hex": hex(&fixed_seed(0x63)),
            "alice_identity_pk_hex": gen.alice_identity_hex,
            "alice_ephemeral_pk_hex": gen.alice_ephemeral_hex,
            "our_pq_sk_hex": gen.sk_b_hex,
            "peer_pq_ct_hex": gen.alice_pq_ct_to_b_hex,
            "our_device_id_hex": gen.bob_device_id_hex,
            "peer_device_id_hex": gen.alice_device_id_hex,
            "transcript_ext_hex": gen.transcript_ext_hex,
        });
        let stdin = serde_json::to_string(&input).unwrap().into_bytes();
        let out = x3dh_respond(&stdin).unwrap();
        assert_eq!(
            out.shared_secret_hex, gen.alice_shared_secret_hex,
            "Rust responder must match Rust initiator shared secret"
        );
    }

    #[test]
    fn verify_shared_secret_constant_time() {
        let a = sibna_core::handshake::x3dh::X3dhResult {
            shared_secret: [1u8; 32],
            dh_results: vec![],
            #[cfg(feature = "pqc")]
            pq_ciphertext: None,
        };
        let b = sibna_core::handshake::x3dh::X3dhResult {
            shared_secret: [1u8; 32],
            dh_results: vec![],
            #[cfg(feature = "pqc")]
            pq_ciphertext: None,
        };
        assert!(verify_shared_secret(&a, &b));
        let c = sibna_core::handshake::x3dh::X3dhResult {
            shared_secret: [2u8; 32],
            dh_results: vec![],
            #[cfg(feature = "pqc")]
            pq_ciphertext: None,
        };
        assert!(!verify_shared_secret(&a, &c));
    }
}
