#include "sibna/safety_number.hpp"
#include "sibna/crypto.hpp"
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

namespace sibna {

// ── SafetyNumber ─────────────────────────────────────────────────────────────
//
// FIX: Phase 5.1 — the C++ SafetyNumber was completely incompatible with
// the Rust core. Key differences that broke cross-SDK verification:
//   1. Missing domain separator "SIBNA_SAFETY_NUMBER_V1" in the hash
//      (Rust: hasher.update(b"SIBNA_SAFETY_NUMBER_V1") at line 54 of safety.rs)
//   2. Output format: Rust uses 80 decimal digits (16 groups of 5),
//      C++ used 60 hex digits (12 groups of 5)
//   3. Grouping: Rust inserts a space every 3 groups (15 digits),
//      C++ inserted a space every group (5 hex chars)
//   4. Fingerprint is the same (first 32 bytes of SHA-512), so verify()
//      would still work if both sides used the same hash input.
// The new implementation matches core/src/safety.rs SafetyNumber::calculate.

static constexpr const char* SAFETY_NUMBER_DOMAIN = "SIBNA_SAFETY_NUMBER_V1";

Result<SafetyNumber> SafetyNumber::calculate(
    const std::array<byte, 32>& our_identity,
    const std::array<byte, 32>& their_identity
) {
    // Sort keys lexicographically for deterministic ordering
    const std::array<byte, 32>* first = &our_identity;
    const std::array<byte, 32>* second = &their_identity;
    
    if (Utils::compare_bytes(our_identity, their_identity) > 0) {
        first = &their_identity;
        second = &our_identity;
    }
    
    // Hash: version(1) + domain separator + first key + second key
    // Matches Rust: hasher.update(&[VERSION]); hasher.update(DOMAIN); hasher.update(first); hasher.update(second);
    bytes concat;
    concat.reserve(1 + 24 + 32 + 32); // 1 + len("SIBNA_SAFETY_NUMBER_V1") + 32 + 32
    concat.push_back(1); // Version 1
    concat.insert(concat.end(), SAFETY_NUMBER_DOMAIN, SAFETY_NUMBER_DOMAIN + 24);
    concat.insert(concat.end(), first->begin(), first->end());
    concat.insert(concat.end(), second->begin(), second->end());
    
    // SHA-512 hash
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return Result<SafetyNumber>(ResultCode::INTERNAL_ERROR, 
            "Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<SafetyNumber>(ResultCode::INTERNAL_ERROR, 
            "Failed to initialize SHA-512");
    }
    
    if (EVP_DigestUpdate(ctx, concat.data(), concat.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<SafetyNumber>(ResultCode::INTERNAL_ERROR, 
            "Failed to update hash");
    }
    
    std::array<byte, 64> hash;
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<SafetyNumber>(ResultCode::INTERNAL_ERROR, 
            "Failed to finalize hash");
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Use first 32 bytes as fingerprint
    std::array<byte, 32> fingerprint;
    std::copy(hash.begin(), hash.begin() + 32, fingerprint.begin());
    
    // Convert to 80 decimal digits (16 groups of 5), grouped with space every 3 groups
    // Matches Rust SafetyNumber::bytes_to_digits:
    //   for each 2-byte chunk: format as 5 decimal digits (value % 100000)
    //   insert space every 3 chunks (i.e., every 15 digits)
    std::string digits_str;
    digits_str.reserve(80 + 5); // 80 digits + up to 5 spaces
    
    for (size_t i = 0; i < 16; ++i) {
        if (i > 0 && i % 3 == 0) {
            digits_str += ' ';
        }
        
        // Two bytes -> 16-bit value
        uint16_t value = (static_cast<uint16_t>(fingerprint[i * 2]) << 8) |
                         static_cast<uint16_t>(fingerprint[i * 2 + 1]);
        
        // Format as 5 decimal digits with leading zeros (mod 100000)
        char buf[6];
        std::snprintf(buf, sizeof(buf), "%05u", static_cast<unsigned>(value % 100000));
        digits_str += buf;
    }
    
    return SafetyNumber(digits_str, fingerprint, 1);
}

Result<SafetyNumber> SafetyNumber::parse(const std::string& safety_number) {
    // Remove spaces and validate
    std::string digits;
    digits.reserve(safety_number.size());
    
    for (char c : safety_number) {
        if (std::isdigit(c)) {
            digits.push_back(c);
        } else if (c != ' ') {
            return Result<SafetyNumber>(ResultCode::INVALID_ARGUMENT, 
                "Invalid character in safety number (only digits and spaces allowed)");
        }
    }
    
    if (digits.length() != 80) {
        return Result<SafetyNumber>(ResultCode::INVALID_ARGUMENT, 
            "Safety number must be 80 decimal digits");
    }
    
    // Convert 80 decimal digits back to fingerprint
    // Each 5 digits = 2 bytes (mod 100000)
    std::array<byte, 32> fingerprint;
    for (size_t i = 0; i < 16; ++i) {
        std::string chunk = digits.substr(i * 5, 5);
        uint32_t value = std::stoul(chunk);
        fingerprint[i * 2]     = static_cast<byte>((value >> 8) & 0xFF);
        fingerprint[i * 2 + 1] = static_cast<byte>(value & 0xFF);
    }
    
    // Re-format for display (add spaces every 3 groups of 5 digits)
    std::string formatted;
    for (size_t i = 0; i < digits.length(); i += 5) {
        if (i > 0 && (i / 5) % 3 == 0) {
            formatted += ' ';
        }
        formatted += digits.substr(i, 5);
    }
    
    return SafetyNumber(formatted, fingerprint, 1);
}

bytes SafetyNumber::qr_data() const {
    // QR code data: version + "SB1" prefix + fingerprint (36 bytes total)
    // Matches Rust core SafetyNumber::qr_data and Dart SafetyNumber.qrData
    bytes result;
    result.reserve(1 + 3 + 32);
    result.push_back(static_cast<byte>(version_));
    result.insert(result.end(), {'S', 'B', '1'});
    result.insert(result.end(), fingerprint_.begin(), fingerprint_.end());
    return result;
}

bool SafetyNumber::verify(const SafetyNumber& other) const {
    return Utils::constant_time_equals(fingerprint_, other.fingerprint_);
}

double SafetyNumber::similarity(const SafetyNumber& other) const {
    // Calculate similarity based on matching decimal digits (80 digits total)
    // Matches Rust SafetyNumber::similarity which compares the formatted digits
    std::string digits_a = formatted_number_; // Already formatted with spaces
    std::string digits_b = other.formatted_number_;
    
    // Remove spaces for comparison
    std::string clean_a, clean_b;
    clean_a.reserve(digits_a.size());
    clean_b.reserve(digits_b.size());
    
    for (char c : digits_a) if (std::isdigit(c)) clean_a += c;
    for (char c : digits_b) if (std::isdigit(c)) clean_b += c;
    
    int matches = 0;
    size_t len = std::min(clean_a.size(), clean_b.size());
    for (size_t i = 0; i < len; ++i) {
        if (clean_a[i] == clean_b[i]) {
            matches++;
        }
    }
    
    return static_cast<double>(matches) / 80.0;
}

// ── VerificationQrCode ───────────────────────────────────────────────────────

VerificationQrCode::VerificationQrCode(
    std::array<byte, 32> identity_key,
    std::array<byte, 16> dev_id,
    std::array<byte, 32> safety_fingerprint,
    bool verified
) : identity_key_(std::move(identity_key))
  , device_id_(std::move(dev_id))
  , safety_fingerprint_(std::move(safety_fingerprint))
  , verified_(verified)
{}

bytes VerificationQrCode::to_bytes() const {
    bytes result;
    result.reserve(1 + 32 + 16 + 32 + 1);
    
    result.push_back(static_cast<byte>(version_));
    result.insert(result.end(), identity_key_.begin(), identity_key_.end());
    result.insert(result.end(), device_id_.begin(), device_id_.end());
    result.insert(result.end(), safety_fingerprint_.begin(), safety_fingerprint_.end());
    result.push_back(verified_ ? 1 : 0);
    
    return result;
}

Result<VerificationQrCode> VerificationQrCode::from_bytes(const bytes& data) {
    if (data.size() < 1 + 32 + 16 + 32 + 1) {
        return Result<VerificationQrCode>(ResultCode::INVALID_ARGUMENT, 
            "QR code data too short");
    }
    
    size_t offset = 0;
    
    int version = data[offset++];
    if (version != 1) {
        return Result<VerificationQrCode>(ResultCode::INVALID_ARGUMENT, 
            "Unsupported QR code version");
    }
    
    std::array<byte, 32> identity_key;
    std::copy(data.begin() + offset, data.begin() + offset + 32, identity_key.begin());
    offset += 32;
    
    std::array<byte, 16> dev_id;
    std::copy(data.begin() + offset, data.begin() + offset + 16, dev_id.begin());
    offset += 16;
    
    std::array<byte, 32> safety_fingerprint;
    std::copy(data.begin() + offset, data.begin() + offset + 32, safety_fingerprint.begin());
    offset += 32;
    
    bool verified = data[offset++] != 0;
    
    return VerificationQrCode(identity_key, dev_id, safety_fingerprint, verified);
}

// ── Safety Number Comparison ─────────────────────────────────────────────────

SafetyComparison compare_safety_numbers(
    const SafetyNumber& a,
    const SafetyNumber& b,
    double similarity_threshold
) {
    if (a.verify(b)) {
        return SafetyComparison::MATCH;
    }
    
    double sim = a.similarity(b);
    if (sim >= similarity_threshold) {
        return SafetyComparison::SIMILAR;
    }
    
    return SafetyComparison::MISMATCH;
}

} // namespace sibna
