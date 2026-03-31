#pragma once

#include "types.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace sibna {

// Safety number for identity verification
class SafetyNumber {
public:
    // Calculate safety number from two identity keys
    static Result<SafetyNumber> calculate(
        const std::array<byte, 32>& our_identity,
        const std::array<byte, 32>& their_identity
    );

    // Parse from string
    static Result<SafetyNumber> parse(const std::string& safety_number);

    // Get formatted number
    const std::string& formatted_number() const { return formatted_number_; }

    // Get raw fingerprint
    const std::array<byte, 32>& fingerprint() const { return fingerprint_; }

    // Get QR code data
    bytes qr_data() const;

    // Verify if another safety number matches (constant-time)
    bool verify(const SafetyNumber& other) const;

    // Calculate similarity score
    double similarity(const SafetyNumber& other) const;

    // Get version
    int version() const { return version_; }

private:
    SafetyNumber(std::string formatted, std::array<byte, 32> fingerprint, int version)
        : formatted_number_(std::move(formatted))
        , fingerprint_(std::move(fingerprint))
        , version_(version) {}

    std::string formatted_number_;
    std::array<byte, 32> fingerprint_;
    int version_;
};

// QR Code data for identity verification
class VerificationQrCode {
public:
    VerificationQrCode(
        std::array<byte, 32> identity_key,
        device_id device_id,
        std::array<byte, 32> safety_fingerprint,
        bool verified = false
    );

    // Encode to bytes
    bytes to_bytes() const;

    // Parse from bytes
    static Result<VerificationQrCode> from_bytes(const bytes& data);

    // Mark as verified
    void mark_verified() { verified_ = true; }

    // Check if verified
    bool is_verified() const { return verified_; }

    // Get identity key
    const std::array<byte, 32>& identity_key() const { return identity_key_; }

    // Get device ID
    const device_id& device_id() const { return device_id_; }

    // Get safety fingerprint
    const std::array<byte, 32>& safety_fingerprint() const { return safety_fingerprint_; }

private:
    int version_ = 1;
    std::array<byte, 32> identity_key_;
    device_id device_id_;
    std::array<byte, 32> safety_fingerprint_;
    bool verified_;
};

// Compare two safety numbers
SafetyComparison compare_safety_numbers(
    const SafetyNumber& a,
    const SafetyNumber& b,
    double similarity_threshold = 0.8
);

} // namespace sibna
