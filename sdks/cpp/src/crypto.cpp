#include "sibna/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace sibna {

Result<key> Crypto::generate_key() {
    key result;
    if (RAND_bytes(result.data(), static_cast<int>(result.size())) != 1) {
        return Result<key>(ResultCode::INTERNAL_ERROR, "Failed to generate random key");
    }
    return result;
}

Result<bytes> Crypto::random_bytes(size_t length) {
    bytes result(length);
    if (RAND_bytes(result.data(), static_cast<int>(result.size())) != 1) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to generate random bytes");
    }
    return result;
}

Result<bytes> Crypto::encrypt(
    const key& key,
    const bytes& plaintext,
    const bytes& associated_data
) {
    try {
        Utils::validate_key_length(key);
        Utils::validate_message_size(plaintext);
    } catch (const ValidationError& e) {
        return Result<bytes>(ResultCode::INVALID_ARGUMENT, e.what());
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to create cipher context");
    }

    // Generate nonce
    nonce iv;
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to generate nonce");
    }

    // FIX: ChaCha20-Poly1305 requires a two-phase OpenSSL init:
    //   Phase 1 — set algorithm, no key/iv yet (pass nullptr, nullptr)
    //   Phase 2 — set explicit IV length, then init key+iv
    // Without Phase 1 first, the IV length control call is ignored on some
    // OpenSSL versions and a 16-byte IV may be used instead of the 12-byte
    // RFC 8439 nonce, producing ciphertext incompatible with other SDK implementations.
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                           nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to init cipher");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                             static_cast<int>(NONCE_LENGTH), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to set IV length");
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to initialize encryption");
    }

    // Set associated data
    if (!associated_data.empty()) {
        int len;
        if (EVP_EncryptUpdate(ctx, nullptr, &len, 
                              associated_data.data(), 
                              static_cast<int>(associated_data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to set associated data");
        }
    }

    // Encrypt
    bytes ciphertext(plaintext.size());
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                          plaintext.data(), 
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::ENCRYPTION_FAILED, "Encryption failed");
    }
    int ciphertext_len = len;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::ENCRYPTION_FAILED, "Encryption finalization failed");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // Get tag
    std::array<byte, TAG_LENGTH> tag;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LENGTH, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::ENCRYPTION_FAILED, "Failed to get tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    // Combine: nonce + ciphertext + tag
    bytes result;
    result.reserve(iv.size() + ciphertext.size() + tag.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

Result<bytes> Crypto::decrypt(
    const key& key,
    const bytes& ciphertext,
    const bytes& associated_data
) {
    try {
        Utils::validate_key_length(key);
    } catch (const ValidationError& e) {
        return Result<bytes>(ResultCode::INVALID_ARGUMENT, e.what());
    }

    if (ciphertext.size() < NONCE_LENGTH + TAG_LENGTH + 1) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Ciphertext too short");
    }

    // Extract nonce, ciphertext, and tag
    nonce iv;
    std::copy(ciphertext.begin(), ciphertext.begin() + NONCE_LENGTH, iv.begin());

    size_t encrypted_len = ciphertext.size() - NONCE_LENGTH - TAG_LENGTH;
    bytes encrypted(ciphertext.begin() + NONCE_LENGTH, 
                    ciphertext.begin() + NONCE_LENGTH + encrypted_len);

    std::array<byte, TAG_LENGTH> tag;
    std::copy(ciphertext.end() - TAG_LENGTH, ciphertext.end(), tag.begin());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to create cipher context");
    }

    // FIX: Two-phase init (same as encrypt) — set IVLEN before key+IV
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                           nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to init cipher");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                             static_cast<int>(NONCE_LENGTH), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to set IV length");
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to initialize decryption");
    }

    // Set associated data
    if (!associated_data.empty()) {
        int len;
        if (EVP_DecryptUpdate(ctx, nullptr, &len, 
                              associated_data.data(), 
                              static_cast<int>(associated_data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to set associated data");
        }
    }

    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LENGTH, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to set tag");
    }

    // Decrypt
    bytes plaintext(encrypted.size());
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                          encrypted.data(), 
                          static_cast<int>(encrypted.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::DECRYPTION_FAILED, "Decryption failed");
    }
    int plaintext_len = len;

    // Verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<bytes>(ResultCode::AUTHENTICATION_FAILED, "Authentication failed");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

Result<bytes> Crypto::sha256(const bytes& data) {
    bytes result(SHA256_DIGEST_LENGTH);
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to create hash context");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to initialize hash");
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to update hash");
    }

    unsigned int result_len;
    if (EVP_DigestFinal_ex(ctx, result.data(), &result_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to finalize hash");
    }

    EVP_MD_CTX_free(ctx);

    result.resize(result_len);
    return result;
}

Result<bytes> Crypto::hmac_sha256(const key& key, const bytes& data) {
    bytes result(EVP_MAX_MD_SIZE);
    unsigned int result_len;

    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             data.data(), data.size(), result.data(), &result_len) == nullptr) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "HMAC failed");
    }

    result.resize(result_len);
    return result;
}

Result<bytes> Crypto::sha512(const bytes& data) {
    bytes result(SHA512_DIGEST_LENGTH);
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to create hash context");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to initialize SHA-512");
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to update hash");
    }

    unsigned int result_len;
    if (EVP_DigestFinal_ex(ctx, result.data(), &result_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to finalize hash");
    }

    EVP_MD_CTX_free(ctx);
    result.resize(result_len);
    return result;
}

Result<key> Crypto::hkdf(
    const bytes& ikm,
    const bytes& salt,
    const bytes& info
) {
    // HKDF-Extract then HKDF-Expand using HMAC-SHA256
    // Extract: PRK = HMAC-Hash(salt, IKM)
    
    // Use salt as key for HMAC (pad with zeros if shorter than KEY_LENGTH)
    key salt_key{};
    if (!salt.empty()) {
        std::copy(salt.begin(), salt.begin() + std::min(salt.size(), size_t(KEY_LENGTH)), salt_key.begin());
    }
    
    // IKM: use actual IKM or zero-filled if empty
    bytes prk_input = ikm.empty() ? bytes(KEY_LENGTH, 0) : ikm;
    auto prk = hmac_sha256(salt_key, prk_input);
    if (prk.is_err()) {
        return Result<key>(prk.code(), prk.message());
    }
    
    // Expand: OKM = T(1) || T(2) || ... where T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
    key result;
    bytes prev;
    size_t offset = 0;
    
    for (uint8_t i = 1; offset < KEY_LENGTH; ++i) {
        bytes t_input;
        t_input.insert(t_input.end(), prev.begin(), prev.end());
        t_input.insert(t_input.end(), info.begin(), info.end());
        t_input.push_back(i);
        
        key prk_key{};
        std::copy(prk.value().begin(), prk.value().begin() + std::min(prk.value().size(), size_t(KEY_LENGTH)), prk_key.begin());
        auto t = hmac_sha256(prk_key, t_input);
        if (t.is_err()) {
            return Result<key>(t.code(), t.message());
        }
        
        size_t to_copy = std::min(t.value().size(), KEY_LENGTH - offset);
        std::copy(t.value().begin(), t.value().begin() + to_copy, result.begin() + offset);
        offset += to_copy;
        prev = t.value();
    }
    
    return result;
}

// ── Message Padding ───────────────────────────────────────────────────────────
//
// FIX: Phase 5.2 — Crypto::pad/unpad were called by test_crypto.cpp but
// never implemented. The implementation matches the Rust core
// core/src/crypto/padding.rs pad_message/unpad_message exactly.
//
// Format: [ prefix_len(1) | prefix_noise(1..8) | plaintext | padding | pad_len(2, LE) ]
// Total output is a multiple of 1024 bytes. extra_blocks ∈ [0, 7] per SIBNA-2026-018.

static constexpr size_t PADDING_BLOCK = 1024;
static constexpr size_t MAX_EXTRA_BLOCKS = 7;
static constexpr size_t MAX_PADDING_BYTES = 65535;
static constexpr size_t MIN_PREFIX_LEN = 1;
static constexpr size_t MAX_PREFIX_LEN = 8;

Result<bytes> Crypto::pad(const bytes& plaintext) {
    // 1. Random prefix_len in [1, 8]
    std::array<byte, 1> prefix_len_buf;
    if (RAND_bytes(prefix_len_buf.data(), 1) != 1) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "RAND_bytes failed");
    }
    size_t prefix_len = (prefix_len_buf[0] % 8) + 1;

    bytes prefix_noise(prefix_len);
    if (RAND_bytes(prefix_noise.data(), static_cast<int>(prefix_len)) != 1) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "RAND_bytes failed");
    }

    // 2. Compute minimum total and min_pad_len
    size_t min_total = 1 + prefix_len + plaintext.size() + 2;
    size_t remainder = min_total % PADDING_BLOCK;
    size_t min_pad_len = (remainder == 0) ? 0 : PADDING_BLOCK - remainder;

    // 3. SIBNA-2026-018: randomize extra blocks
    size_t max_blocks_for_budget = (min_pad_len > MAX_PADDING_BYTES) ? 0 :
        (MAX_PADDING_BYTES - min_pad_len) / PADDING_BLOCK;
    size_t cap_blocks = std::min(MAX_EXTRA_BLOCKS, max_blocks_for_budget);

    std::array<byte, 1> extra_buf;
    if (RAND_bytes(extra_buf.data(), 1) != 1) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "RAND_bytes failed");
    }
    size_t extra_blocks = extra_buf[0] % (cap_blocks + 1);
    size_t pad_len = min_pad_len + extra_blocks * PADDING_BLOCK;

    if (pad_len > MAX_PADDING_BYTES) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "pad_len exceeds maximum");
    }

    // 4. Build output: [prefix_len | prefix_noise | plaintext | padding | pad_len(2 LE)]
    size_t total = min_total + pad_len;
    bytes out;
    out.reserve(total);

    out.push_back(static_cast<byte>(prefix_len));
    out.insert(out.end(), prefix_noise.begin(), prefix_noise.end());
    out.insert(out.end(), plaintext.begin(), plaintext.end());

    if (pad_len > 0) {
        bytes rand_pad(pad_len);
        if (RAND_bytes(rand_pad.data(), static_cast<int>(pad_len)) != 1) {
            return Result<bytes>(ResultCode::INTERNAL_ERROR, "RAND_bytes failed");
        }
        out.insert(out.end(), rand_pad.begin(), rand_pad.end());
    }

    // 2-byte little-endian pad_len
    out.push_back(static_cast<byte>(pad_len & 0xFF));
    out.push_back(static_cast<byte>((pad_len >> 8) & 0xFF));

    return out;
}

Result<bytes> Crypto::unpad(const bytes& padded) {
    if (padded.size() < 4) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Padded payload too short");
    }

    size_t prefix_len = padded[0];
    if (prefix_len < MIN_PREFIX_LEN || prefix_len > MAX_PREFIX_LEN) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Invalid prefix length");
    }

    if (1 + prefix_len + 2 > padded.size()) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Padded payload truncated");
    }

    // Trailing 2-byte little-endian pad_len
    size_t lo = padded[padded.size() - 2];
    size_t hi = padded[padded.size() - 1];
    size_t pad_len = lo | (hi << 8);

    size_t total_overhead = 1 + prefix_len + pad_len + 2;
    if (total_overhead > padded.size()) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Invalid padding length");
    }

    size_t plaintext_len = padded.size() - total_overhead;
    size_t start = 1 + prefix_len;

    bytes plaintext(plaintext_len);
    std::copy(padded.begin() + start, padded.begin() + start + plaintext_len, plaintext.begin());

    return plaintext;
}

} // namespace sibna
