use blake3::Hasher;
use hkdf::Hkdf;
use sha2::Sha256;
use sibna_core::handshake::x3dh::x3dh_initiator_v3;
use x25519_dalek::{PublicKey, StaticSecret};

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn debug_x3dh() {
    let alice_seed = [0x61u8; 32];
    let bob_seed = [0x62u8; 32];
    let alice_id = StaticSecret::from(alice_seed);
    let alice_id_pub = PublicKey::from(&alice_id);
    let alice_eph = StaticSecret::from([0x65u8; 32]);
    let alice_eph_pub = PublicKey::from(&alice_eph);
    let bob_id = StaticSecret::from(bob_seed);
    let bob_id_pub = PublicKey::from(&bob_id);
    let bob_spk = StaticSecret::from([0x63u8; 32]);
    let bob_spk_pub = PublicKey::from(&bob_spk);
    let bob_opk = StaticSecret::from([0x64u8; 32]);
    let bob_opk_pub = PublicKey::from(&bob_opk);

    let mut hasher = blake3::Hasher::new();
    hasher.update(alice_id_pub.as_bytes());
    hasher.update(alice_eph_pub.as_bytes());
    hasher.update(bob_id_pub.as_bytes());
    hasher.update(bob_spk_pub.as_bytes());
    hasher.update(bob_opk_pub.as_bytes());
    hasher.update(&[0u8; 16]);
    hasher.update(&[0u8; 16]);
    let transcript_hash: [u8; 32] = hasher.finalize().into();
    println!("rust_transcript={}", hex(&transcript_hash));

    let combined_transcript: [u8; 32] = {
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &transcript_hash);
        let mut out = [0u8; 32];
        hk.expand(b"SibnaX3DH_TranscriptBind_v3", &mut out).unwrap();
        out
    };
    println!("rust_combined={}", hex(&combined_transcript));

    let dh1 = alice_id.diffie_hellman(&bob_spk_pub);
    let dh2 = alice_eph.diffie_hellman(&bob_id_pub);
    let dh3 = alice_eph.diffie_hellman(&bob_spk_pub);
    let dh4 = alice_eph.diffie_hellman(&bob_opk_pub);
    println!("rust_dh1={}", hex(dh1.as_bytes()));
    println!("rust_dh2={}", hex(dh2.as_bytes()));
    println!("rust_dh3={}", hex(dh3.as_bytes()));
    println!("rust_dh4={}", hex(dh4.as_bytes()));

    let full = x3dh_initiator_v3(
        &alice_id,
        &alice_eph,
        &bob_id_pub,
        &bob_spk_pub,
        Some(&bob_opk_pub),
        None,
        &[0u8; 16],
        &[0u8; 16],
        &[0u8; 32],
    )
    .unwrap();
    println!("rust_full_ss={}", hex(&full.shared_secret));
    println!(
        "rust_expected={}",
        "e03c8496aba67b549b979041d142e146e7b4a16acd72d11d068ab2c1a7a9c204"
    );
}
