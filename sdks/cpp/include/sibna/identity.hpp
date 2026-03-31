#pragma once

#include "types.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace sibna {

// Identity key pair
class IdentityKeyPair {
public:
    // Create from existing keys
    IdentityKeyPair(
        std::array<byte, 32> ed25519_public,
        std::array<byte, 32> x25519_public
    );

    // Generate a new key pair
    static Result<IdentityKeyPair> generate();

    // Get Ed25519 public key
    const std::array<byte, 32>& ed25519_public_key() const { return ed25519_public_key_; }

    // Get X25519 public key
    const std::array<byte, 32>& x25519_public_key() const { return x25519_public_key_; }

    // Get key fingerprint
    std::string fingerprint() const { return fingerprint_; }

    // Sign data
    Result<signature> sign(const bytes& data) const;

    // Verify signature
    Result<bool> verify(const bytes& data, const signature& sig) const;

private:
    std::array<byte, 32> ed25519_public_key_;
    std::array<byte, 32> x25519_public_key_;
    std::string fingerprint_;
};

// Prekey bundle for X3DH handshake
class PreKeyBundle {
public:
    PreKeyBundle(
        std::array<byte, 32> identity_key,
        std::array<byte, 32> signed_prekey,
        signature sig,
        std::optional<std::array<byte, 32>> onetime_prekey = std::nullopt
    );

    // Serialize to bytes
    bytes to_bytes() const;

    // Deserialize from bytes
    static Result<PreKeyBundle> from_bytes(const bytes& data);

    // Get identity key
    const std::array<byte, 32>& identity_key() const { return identity_key_; }

    // Get signed prekey
    const std::array<byte, 32>& signed_prekey() const { return signed_prekey_; }

    // Get signature
    const signature& sig() const { return signature_; }

    // Get one-time prekey (if present)
    const std::optional<std::array<byte, 32>>& onetime_prekey() const { return onetime_prekey_; }

    // Check if expired (older than 7 days)
    bool is_expired() const;

    // Verify signature
    Result<bool> verify_signature(const std::array<byte, 32>& identity_public_key) const;

private:
    std::array<byte, 32> identity_key_;
    std::array<byte, 32> signed_prekey_;
    signature signature_;
    std::optional<std::array<byte, 32>> onetime_prekey_;
    std::chrono::system_clock::time_point timestamp_;
};

} // namespace sibna
