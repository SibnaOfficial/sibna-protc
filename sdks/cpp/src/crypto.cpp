#include "sibna/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

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

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, 
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

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, 
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

} // namespace sibna
