#include "sibna/x3dh.hpp"
#include "sibna/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace sibna {

// ── X3DH ─────────────────────────────────────────────────────────────────────
//
// Matches the Rust core handshake::x3dh implementation exactly:
//   - Transcript hash via SHA-256 (fallback for blake3)
//   - HKDF-based transcript binding with "SibnaX3DH_TranscriptBind_v3"
//   - Shared secret derivation via HKDF with "SibnaX3DH_v3"
//   - DH computation order: initiator and responder perspectives
//   - X25519 identity key for DH, Ed25519 identity key for signing

// ── Helpers ──────────────────────────────────────────────────────────────────

/// SHA-256 fallback for blake3 transcript hash.
/// Concatenates all parts and hashes them.
static key sha256_transcript(const bytes& data) {
    key result;
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return result;
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, result.data(), &len);
    EVP_MD_CTX_free(ctx);
    return result;
}

/// HKDF-SHA256 extract+expand for transcript binding.
/// salt=transcript_hash_ext, ikm=transcript_hash, info="SibnaX3DH_TranscriptBind_v3"
static key transcript_bind(
    const key& transcript_hash,
    const std::array<byte, 32>& transcript_hash_ext
) {
    // HKDF-Extract(salt=transcript_hash_ext, ikm=transcript_hash)
    key salt_key{};
    std::copy(transcript_hash_ext.begin(), transcript_hash_ext.end(), salt_key.begin());
    auto prk_result = Crypto::hmac_sha256(salt_key, bytes(transcript_hash.begin(), transcript_hash.end()));
    if (prk_result.is_err()) {
        return key{};
    }
    key prk = prk_result.value();

    // HKDF-Expand(PRK, info="SibnaX3DH_TranscriptBind_v3", len=32)
    bytes info = {'S','i','b','n','a','X','3','D','H','_','T','r','a','n','s','c','r','i','p','t','B','i','n','d','_','v','3'};
    bytes t_input;
    t_input.insert(t_input.end(), info.begin(), info.end());
    t_input.push_back(1);
    auto t = Crypto::hmac_sha256(prk, t_input);
    if (t.is_err()) {
        return key{};
    }
    return key(t.value().begin(), t.value().begin() + 32);
}

/// Derive X3DH shared secret from DH results + transcript hash
/// HKDF(salt=combined_transcript, ikm=concat(dh1,dh2,dh3[,dh4]), info="SibnaX3DH_v3")
static key derive_shared_secret(
    const key& dh1,
    const key& dh2,
    const key& dh3,
    const std::optional<key>& dh4,
    const key& combined_transcript
) {
    bytes concatenated;
    concatenated.reserve(KEY_LENGTH * 4);
    concatenated.insert(concatenated.end(), dh1.begin(), dh1.end());
    concatenated.insert(concatenated.end(), dh2.begin(), dh2.end());
    concatenated.insert(concatenated.end(), dh3.begin(), dh3.end());
    if (dh4.has_value()) {
        concatenated.insert(concatenated.end(), dh4->begin(), dh4->end());
    }

    bytes info = {'S','i','b','n','a','X','3','D','H','_','v','3'};
    auto result = Crypto::hkdf(concatenated, bytes(combined_transcript.begin(), combined_transcript.end()), info);
    if (result.is_err()) {
        return key{};
    }
    return result.value();
}

/// Compute X25519 DH
static key x25519_dh(const key& private_key, const key& public_key) {
    auto result = X25519::diffie_hellman(private_key, public_key);
    if (result.is_err()) {
        return key{};
    }
    return result.value();
}

/// Get X25519 public key from private key
static key x25519_public(const key& private_key) {
    auto result = X25519::generate_keypair_from_private(private_key);
    if (result.is_err()) {
        return key{};
    }
    return result.value().second;
}

// ── Initiator ────────────────────────────────────────────────────────────────

Result<X3dhResult> x3dh_initiator(
    const key& our_identity_private,
    const key& our_ephemeral_private,
    const key& peer_identity_public,
    const key& peer_signed_prekey,
    const std::optional<key>& peer_onetime_prekey,
    const device_id& our_device_id,
    const device_id& peer_device_id,
    const std::array<byte, 32>& transcript_hash_ext
) {
    // Compute public keys
    key our_identity_pub = x25519_public(our_identity_private);
    key our_ephemeral_pub = x25519_public(our_ephemeral_private);

    // DH1: Our identity + peer's signed prekey
    key dh1 = x25519_dh(our_identity_private, peer_signed_prekey);
    // DH2: Our ephemeral + peer's identity
    key dh2 = x25519_dh(our_ephemeral_private, peer_identity_public);
    // DH3: Our ephemeral + peer's signed prekey
    key dh3 = x25519_dh(our_ephemeral_private, peer_signed_prekey);

    std::vector<key> dh_results = {dh1, dh2, dh3};

    // DH4: Our ephemeral + peer's one-time prekey (if available)
    std::optional<key> dh4;
    if (peer_onetime_prekey.has_value()) {
        dh4 = x25519_dh(our_ephemeral_private, *peer_onetime_prekey);
        dh_results.push_back(*dh4);
    }

    // Transcript hash (only PUBLIC keys)
    // Order: [our_id, our_eph, peer_id, peer_spk, opt(peer_opk), our_dev, peer_dev]
    bytes transcript_input;
    transcript_input.reserve(32 * 5 + 16 + 16);
    transcript_input.insert(transcript_input.end(), our_identity_pub.begin(), our_identity_pub.end());
    transcript_input.insert(transcript_input.end(), our_ephemeral_pub.begin(), our_ephemeral_pub.end());
    transcript_input.insert(transcript_input.end(), peer_identity_public.begin(), peer_identity_public.end());
    transcript_input.insert(transcript_input.end(), peer_signed_prekey.begin(), peer_signed_prekey.end());
    if (peer_onetime_prekey.has_value()) {
        transcript_input.insert(transcript_input.end(), peer_onetime_prekey->begin(), peer_onetime_prekey->end());
    }
    transcript_input.insert(transcript_input.end(), our_device_id.begin(), our_device_id.end());
    transcript_input.insert(transcript_input.end(), peer_device_id.begin(), peer_device_id.end());

    key transcript_hash = sha256_transcript(transcript_input);

    // HKDF-based transcript binding
    key combined_transcript = transcript_bind(transcript_hash, transcript_hash_ext);

    // Derive shared secret
    key shared_secret = derive_shared_secret(dh1, dh2, dh3, dh4, combined_transcript);

    return X3dhResult{shared_secret, dh_results};
}

// ── Responder ────────────────────────────────────────────────────────────────

Result<X3dhResult> x3dh_responder(
    const key& our_identity_private,
    const key& our_signed_prekey_private,
    const std::optional<key>& our_onetime_prekey_private,
    const key& peer_identity_public,
    const key& peer_ephemeral_public,
    const device_id& our_device_id,
    const device_id& peer_device_id,
    const std::array<byte, 32>& transcript_hash_ext
) {
    // Compute public keys
    key our_identity_pub = x25519_public(our_identity_private);
    key our_spk_pub = x25519_public(our_signed_prekey_private);

    // DH1: Our signed prekey + peer's identity
    key dh1 = x25519_dh(our_signed_prekey_private, peer_identity_public);
    // DH2: Our identity + peer's ephemeral
    key dh2 = x25519_dh(our_identity_private, peer_ephemeral_public);
    // DH3: Our signed prekey + peer's ephemeral
    key dh3 = x25519_dh(our_signed_prekey_private, peer_ephemeral_public);

    std::vector<key> dh_results = {dh1, dh2, dh3};

    // DH4: Our one-time prekey + peer's ephemeral (if available)
    std::optional<key> dh4;
    if (our_onetime_prekey_private.has_value()) {
        key our_opk_pub = x25519_public(*our_onetime_prekey_private);
        dh4 = x25519_dh(*our_onetime_prekey_private, peer_ephemeral_public);
        dh_results.push_back(*dh4);
    }

    // Transcript hash (matching initiator order from initiator's perspective)
    // From responder: [peer_id, peer_eph, our_id, our_spk, opt(our_opk), peer_dev, our_dev]
    bytes transcript_input;
    transcript_input.reserve(32 * 5 + 16 + 16);
    transcript_input.insert(transcript_input.end(), peer_identity_public.begin(), peer_identity_public.end());
    transcript_input.insert(transcript_input.end(), peer_ephemeral_public.begin(), peer_ephemeral_public.end());
    transcript_input.insert(transcript_input.end(), our_identity_pub.begin(), our_identity_pub.end());
    transcript_input.insert(transcript_input.end(), our_spk_pub.begin(), our_spk_pub.end());
    if (our_onetime_prekey_private.has_value()) {
        key our_opk_pub = x25519_public(*our_onetime_prekey_private);
        transcript_input.insert(transcript_input.end(), our_opk_pub.begin(), our_opk_pub.end());
    }
    transcript_input.insert(transcript_input.end(), peer_device_id.begin(), peer_device_id.end());
    transcript_input.insert(transcript_input.end(), our_device_id.begin(), our_device_id.end());

    key transcript_hash = sha256_transcript(transcript_input);

    // HKDF-based transcript binding
    key combined_transcript = transcript_bind(transcript_hash, transcript_hash_ext);

    // Derive shared secret
    key shared_secret = derive_shared_secret(dh1, dh2, dh3, dh4, combined_transcript);

    return X3dhResult{shared_secret, dh_results};
}

// ── Session Key Derivation ──────────────────────────────────────────────────

Result<std::pair<key, key>> x3dh_derive_session_keys(const key& shared_secret) {
    // HKDF(shared_secret, salt="SibnaSession_v3",
    //       info="SibnaRootAndChainKey_v3", length=64)
    bytes salt = {'S','i','b','n','a','S','e','s','s','i','o','n','_','v','3'};
    bytes info = {'S','i','b','n','a','R','o','o','t','A','n','d','C','h','a','i','n','K','e','y','_','v','3'};

    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    key salt_key{};
    std::copy(salt.begin(), salt.end(), salt_key.begin());
    auto prk = Crypto::hmac_sha256(salt_key, bytes(shared_secret.begin(), shared_secret.end()));
    if (prk.is_err()) {
        return Result<std::pair<key, key>>(prk.code(), prk.message());
    }

    // HKDF-Expand to 64 bytes: T(1) || T(2)
    bytes result_64(64);
    bytes prev;

    // T(1) = HMAC(PRK, info || 0x01)
    bytes t1_input;
    t1_input.insert(t1_input.end(), info.begin(), info.end());
    t1_input.push_back(1);
    auto t1 = Crypto::hmac_sha256(prk.value(), t1_input);
    if (t1.is_err()) {
        return Result<std::pair<key, key>>(t1.code(), t1.message());
    }
    std::copy(t1.value().begin(), t1.value().begin() + 32, result_64.begin());
    prev = t1.value();

    // T(2) = HMAC(PRK, T(1) || info || 0x02)
    bytes t2_input;
    t2_input.insert(t2_input.end(), prev.begin(), prev.end());
    t2_input.insert(t2_input.end(), info.begin(), info.end());
    t2_input.push_back(2);
    auto t2 = Crypto::hmac_sha256(prk.value(), t2_input);
    if (t2.is_err()) {
        return Result<std::pair<key, key>>(t2.code(), t2.message());
    }
    std::copy(t2.value().begin(), t2.value().begin() + 32, result_64.begin() + 32);

    key root_key, chain_key;
    std::copy(result_64.begin(), result_64.begin() + 32, root_key.begin());
    std::copy(result_64.begin() + 32, result_64.end(), chain_key.begin());

    return std::make_pair(root_key, chain_key);
}

} // namespace sibna
