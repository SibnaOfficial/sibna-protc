#include "sibna/utils.hpp"
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace sibna {

std::string Utils::bytes_to_base64(const bytes& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    std::string result(buffer_ptr->data, buffer_ptr->length);
    
    BIO_free_all(b64);
    
    return result;
}

bytes Utils::base64_to_bytes(const std::string& base64) {
    BIO* bio = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.length()));
    BIO* b64 = BIO_new(BIO_f_base64());
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    
    bytes result(base64.length());
    int decoded_length = BIO_read(b64, result.data(), static_cast<int>(result.size()));
    
    BIO_free_all(b64);
    
    if (decoded_length < 0) {
        throw ValidationError("base64", "Invalid base64 string");
    }
    
    result.resize(decoded_length);
    return result;
}

std::string Utils::calculate_fingerprint(const bytes& public_key) {
    // Use SHA-256 for fingerprint
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw CryptoError(ResultCode::INTERNAL_ERROR, "Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw CryptoError(ResultCode::INTERNAL_ERROR, "Failed to initialize hash");
    }
    
    if (EVP_DigestUpdate(ctx, public_key.data(), public_key.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw CryptoError(ResultCode::INTERNAL_ERROR, "Failed to update hash");
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len;
    
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw CryptoError(ResultCode::INTERNAL_ERROR, "Failed to finalize hash");
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Return first 8 bytes as hex
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < 8 && i < hash_len; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    
    return oss.str();
}

std::string Utils::format_safety_number(const std::string& safety_number) {
    std::string digits;
    digits.reserve(safety_number.size());
    
    // Extract only digits
    for (char c : safety_number) {
        if (std::isdigit(c)) {
            digits.push_back(c);
        }
    }
    
    // Format in groups of 5
    std::ostringstream oss;
    for (size_t i = 0; i < digits.size(); i += 5) {
        if (i > 0) {
            oss << ' ';
        }
        oss << digits.substr(i, std::min(size_t(5), digits.size() - i));
    }
    
    return oss.str();
}

} // namespace sibna
