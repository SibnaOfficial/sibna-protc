#include "sibna/identity.hpp"
#include "sibna/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace sibna {

// ── IdentityKeyPair ──────────────────────────────────────────────────────────

IdentityKeyPair::IdentityKeyPair(
    std::array<byte, 32> ed25519_public,
    std::array<byte, 32> x25519_public
) : ed25519_public_key_(std::move(ed25519_public))
  , x25519_public_key_(std::move(x25519_public))
{
    // Generate fingerprint from Ed25519 public key
    bytes pk_bytes(ed25519_public_key_.begin(), ed25519_public_key_.end());
    fingerprint_ = Utils::calculate_fingerprint(pk_bytes);
}

Result<IdentityKeyPair> IdentityKeyPair::generate() {
    // Generate Ed25519 keypair using OpenSSL
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to create Ed25519 context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to initialize Ed25519 keygen");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to generate Ed25519 keypair");
    }

    EVP_PKEY_CTX_free(ctx);

    // Extract public key
    std::array<byte, 32> ed25519_pub;
    size_t pub_len = ed25519_pub.size();
    if (EVP_PKEY_get_raw_public_key(pkey, ed25519_pub.data(), &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to extract Ed25519 public key");
    }

    // Extract private key seed (32 bytes for Ed25519)
    bytes ed25519_priv(32);
    size_t priv_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, ed25519_priv.data(), &priv_len) != 1) {
        EVP_PKEY_free(pkey);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to extract Ed25519 private key");
    }

    // For X25519, generate a separate keypair
    EVP_PKEY_CTX* x25519_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!x25519_ctx) {
        EVP_PKEY_free(pkey);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to create X25519 context");
    }

    if (EVP_PKEY_keygen_init(x25519_ctx) <= 0) {
        EVP_PKEY_CTX_free(x25519_ctx);
        EVP_PKEY_free(pkey);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to initialize X25519 keygen");
    }

    EVP_PKEY* x25519_pkey = nullptr;
    if (EVP_PKEY_keygen(x25519_ctx, &x25519_pkey) <= 0) {
        EVP_PKEY_CTX_free(x25519_ctx);
        EVP_PKEY_free(pkey);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to generate X25519 keypair");
    }

    EVP_PKEY_CTX_free(x25519_ctx);

    std::array<byte, 32> x25519_pub;
    size_t x25519_pub_len = x25519_pub.size();
    if (EVP_PKEY_get_raw_public_key(x25519_pkey, x25519_pub.data(), &x25519_pub_len) != 1) {
        EVP_PKEY_free(x25519_pkey);
        EVP_PKEY_free(pkey);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to extract X25519 public key");
    }

    // Extract X25519 private key
    bytes x25519_priv(32);
    size_t x25519_priv_len = 32;
    if (EVP_PKEY_get_raw_private_key(x25519_pkey, x25519_priv.data(), &x25519_priv_len) != 1) {
        EVP_PKEY_free(x25519_pkey);
        EVP_PKEY_free(pkey);
        return Result<IdentityKeyPair>(ResultCode::INTERNAL_ERROR, 
            "Failed to extract X25519 private key");
    }

    EVP_PKEY_free(x25519_pkey);
    EVP_PKEY_free(pkey);

    // Create identity with private keys
    IdentityKeyPair identity(ed25519_pub, x25519_pub);
    identity.ed25519_private_key_ = SecureBuffer(std::move(ed25519_priv));
    identity.x25519_private_key_ = SecureBuffer(std::move(x25519_priv));

    return identity;
}

Result<signature> IdentityKeyPair::sign(const bytes& data) const {
    if (ed25519_private_key_.empty()) {
        return Result<signature>(ResultCode::INVALID_STATE, 
            "Private key not available - use generate() to create identity");
    }

    // Create EVP_PKEY from private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        ed25519_private_key_.data(), ed25519_private_key_.size()
    );
    if (!pkey) {
        return Result<signature>(ResultCode::INTERNAL_ERROR, "Failed to create private key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return Result<signature>(ResultCode::INTERNAL_ERROR, "Failed to create sign context");
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<signature>(ResultCode::INTERNAL_ERROR, "Failed to init sign");
    }

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, nullptr, &sig_len, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<signature>(ResultCode::INTERNAL_ERROR, "Failed to get signature length");
    }

    if (sig_len != SIGNATURE_LENGTH) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<signature>(ResultCode::INTERNAL_ERROR, "Unexpected signature length");
    }

    // Sign
    signature sig;
    if (EVP_DigestSign(ctx, sig.data(), &sig_len, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<signature>(ResultCode::INTERNAL_ERROR, "Failed to sign");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return sig;
}

Result<bool> IdentityKeyPair::verify(const bytes& data, const signature& sig) const {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, 
        ed25519_public_key_.data(), ed25519_public_key_.size()
    );
    if (!pkey) {
        return Result<bool>(ResultCode::INTERNAL_ERROR, "Failed to create public key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return Result<bool>(ResultCode::INTERNAL_ERROR, "Failed to create verify context");
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<bool>(ResultCode::INTERNAL_ERROR, "Failed to init verify");
    }

    int result = EVP_DigestVerify(ctx, sig.data(), sig.size(), data.data(), data.size());
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result == 1;
}

void IdentityKeyPair::clear_private_keys() {
    ed25519_private_key_.clear();
    x25519_private_key_.clear();
}

// ── PreKeyBundle ─────────────────────────────────────────────────────────────

PreKeyBundle::PreKeyBundle(
    std::array<byte, 32> identity_key,
    std::array<byte, 32> signed_prekey,
    signature sig,
    std::optional<std::array<byte, 32>> onetime_prekey
) : identity_key_(std::move(identity_key))
  , signed_prekey_(std::move(signed_prekey))
  , signature_(std::move(sig))
  , onetime_prekey_(std::move(onetime_prekey))
  , timestamp_(std::chrono::system_clock::now())
{}

bytes PreKeyBundle::to_bytes() const {
    bytes result;
    result.reserve(32 + 32 + 64 + (onetime_prekey_ ? 32 : 0) + 1);
    
    result.insert(result.end(), identity_key_.begin(), identity_key_.end());
    result.insert(result.end(), signed_prekey_.begin(), signed_prekey_.end());
    result.insert(result.end(), signature_.begin(), signature_.end());
    
    // Flag for one-time prekey
    result.push_back(onetime_prekey_ ? 1 : 0);
    if (onetime_prekey_) {
        result.insert(result.end(), onetime_prekey_->begin(), onetime_prekey_->end());
    }
    
    return result;
}

Result<PreKeyBundle> PreKeyBundle::from_bytes(const bytes& data) {
    if (data.size() < 32 + 32 + 64 + 1) {
        return Result<PreKeyBundle>(ResultCode::INVALID_ARGUMENT, 
            "PreKeyBundle data too short");
    }
    
    size_t offset = 0;
    
    std::array<byte, 32> identity_key;
    std::copy(data.begin() + offset, data.begin() + offset + 32, identity_key.begin());
    offset += 32;
    
    std::array<byte, 32> signed_prekey;
    std::copy(data.begin() + offset, data.begin() + offset + 32, signed_prekey.begin());
    offset += 32;
    
    signature sig;
    std::copy(data.begin() + offset, data.begin() + offset + 64, sig.begin());
    offset += 64;
    
    bool has_onetime = data[offset++] != 0;
    
    std::optional<std::array<byte, 32>> onetime_prekey;
    if (has_onetime) {
        if (data.size() < offset + 32) {
            return Result<PreKeyBundle>(ResultCode::INVALID_ARGUMENT, 
                "PreKeyBundle missing one-time prekey data");
        }
        std::array<byte, 32> otp;
        std::copy(data.begin() + offset, data.begin() + offset + 32, otp.begin());
        onetime_prekey = otp;
        offset += 32;
    }
    
    return PreKeyBundle(identity_key, signed_prekey, sig, onetime_prekey);
}

bool PreKeyBundle::is_expired() const {
    auto age = std::chrono::system_clock::now() - timestamp_;
    return age > std::chrono::hours(24 * 7); // 7 days
}

Result<bool> PreKeyBundle::verify_signature(
    const std::array<byte, 32>& identity_public_key) const {
    // Create a temporary identity to verify the signature
    IdentityKeyPair temp_id(identity_public_key, {});
    
    // Must include domain separator to match Rust core (lib.rs:554-555)
    bytes signed_data;
    signed_data.reserve(20 + 32);
    signed_data.insert(signed_data.end(), b"SibnaSignedPreKey_v3", b"SibnaSignedPreKey_v3" + 20);
    signed_data.insert(signed_data.end(), signed_prekey_.begin(), signed_prekey_.end());
    
    return temp_id.verify(signed_data, signature_);
}

} // namespace sibna
