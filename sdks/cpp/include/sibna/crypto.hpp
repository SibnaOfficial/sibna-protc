#pragma once

#include "types.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace sibna {

// Standalone cryptographic operations
class Crypto {
public:
    // Delete constructor - static class
    Crypto() = delete;

    // Generate a random 32-byte encryption key
    static Result<key> generate_key();

    // Generate random bytes
    static Result<bytes> random_bytes(size_t length);

    // Encrypt data with a key
    static Result<bytes> encrypt(
        const key& key,
        const bytes& plaintext,
        const bytes& associated_data = {}
    );

    // Decrypt data with a key
    static Result<bytes> decrypt(
        const key& key,
        const bytes& ciphertext,
        const bytes& associated_data = {}
    );

    // HKDF key derivation
    static Result<key> hkdf(
        const bytes& ikm,
        const bytes& salt = {},
        const bytes& info = {}
    );

    // HMAC-SHA256
    static Result<bytes> hmac_sha256(
        const key& key,
        const bytes& data
    );

    // SHA-256 hash
    static Result<bytes> sha256(const bytes& data);

    // SHA-512 hash
    static Result<bytes> sha512(const bytes& data);
};

// ChaCha20-Poly1305 encryption
class ChaCha20Poly1305 {
public:
    // Encrypt
    static Result<bytes> encrypt(
        const key& key,
        const bytes& plaintext,
        const bytes& associated_data = {}
    );

    // Decrypt
    static Result<bytes> decrypt(
        const key& key,
        const bytes& ciphertext,
        const bytes& associated_data = {}
    );
};

// X25519 key exchange
class X25519 {
public:
    // Generate a key pair
    static Result<std::pair<key, key>> generate_keypair();

    // Perform Diffie-Hellman
    static Result<key> diffie_hellman(
        const key& private_key,
        const key& public_key
    );
};

// Ed25519 signatures
class Ed25519 {
public:
    // Generate a key pair
    static Result<std::pair<key, key>> generate_keypair();

    // Sign data
    static Result<signature> sign(
        const key& private_key,
        const bytes& message
    );

    // Verify signature
    static Result<bool> verify(
        const key& public_key,
        const bytes& message,
        const signature& sig
    );
};

} // namespace sibna
