#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <memory>
#include <optional>
#include <functional>

namespace sibna {

// Version information
constexpr uint32_t PROTOCOL_VERSION = 8;
constexpr uint32_t MIN_COMPATIBLE_VERSION = 7;
constexpr const char* VERSION_STRING = "1.0.0";

// Constants
constexpr size_t KEY_LENGTH = 32;
constexpr size_t NONCE_LENGTH = 12;
constexpr size_t TAG_LENGTH = 16;
constexpr size_t SIGNATURE_LENGTH = 64;
constexpr size_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10 MB
constexpr size_t MAX_GROUP_SIZE = 1000;

// Type aliases
using byte = uint8_t;
using bytes = std::vector<byte>;
using key = std::array<byte, KEY_LENGTH>;
using nonce = std::array<byte, NONCE_LENGTH>;
using signature = std::array<byte, SIGNATURE_LENGTH>;
using group_id = std::array<byte, 32>;
using device_id = std::array<byte, 16>;

// Forward declarations
class Context;
class Session;
class IdentityKeyPair;
class GroupSession;
class SafetyNumber;
class PreKeyBundle;

// Custom deleter for secure memory
template<typename T>
struct secure_deleter {
    void operator()(T* ptr) const {
        if (ptr) {
            // Zeroize memory before deletion
            std::fill_n(reinterpret_cast<byte*>(ptr), sizeof(T), 0);
            delete ptr;
        }
    }
};

// Secure unique pointer
template<typename T>
using secure_unique_ptr = std::unique_ptr<T, secure_deleter<T>>;

// Result type
enum class ResultCode : int {
    OK = 0,
    INVALID_ARGUMENT = 1,
    INVALID_KEY = 2,
    ENCRYPTION_FAILED = 3,
    DECRYPTION_FAILED = 4,
    OUT_OF_MEMORY = 5,
    INVALID_STATE = 6,
    SESSION_NOT_FOUND = 7,
    KEY_NOT_FOUND = 8,
    RATE_LIMIT_EXCEEDED = 9,
    INTERNAL_ERROR = 10,
    BUFFER_TOO_SMALL = 11,
    INVALID_CIPHERTEXT = 12,
    AUTHENTICATION_FAILED = 13,
    NOT_INITIALIZED = 14,
};

// Result class
template<typename T>
class Result {
public:
    Result(T value) : code_(ResultCode::OK), value_(std::move(value)) {}
    Result(ResultCode code) : code_(code) {}
    Result(ResultCode code, std::string message) 
        : code_(code), message_(std::move(message)) {}

    bool is_ok() const { return code_ == ResultCode::OK; }
    bool is_err() const { return code_ != ResultCode::OK; }

    ResultCode code() const { return code_; }
    const std::string& message() const { return message_; }

    T& value() & {
        if (is_err()) {
            throw std::runtime_error("Cannot get value from error result: " + message_);
        }
        return value_.value();
    }

    T&& value() && {
        if (is_err()) {
            throw std::runtime_error("Cannot get value from error result: " + message_);
        }
        return std::move(value_.value());
    }

    const T& value() const & {
        if (is_err()) {
            throw std::runtime_error("Cannot get value from error result: " + message_);
        }
        return value_.value();
    }

    T value_or(T default_value) const {
        return is_ok() ? value_.value() : std::move(default_value);
    }

private:
    ResultCode code_;
    std::optional<T> value_;
    std::string message_;
};

// Void result specialization
template<>
class Result<void> {
public:
    Result() : code_(ResultCode::OK) {}
    Result(ResultCode code) : code_(code) {}
    Result(ResultCode code, std::string message) 
        : code_(code), message_(std::move(message)) {}

    bool is_ok() const { return code_ == ResultCode::OK; }
    bool is_err() const { return code_ != ResultCode::OK; }

    ResultCode code() const { return code_; }
    const std::string& message() const { return message_; }

private:
    ResultCode code_;
    std::string message_;
};

// Configuration struct
struct Config {
    bool enable_forward_secrecy = true;
    bool enable_post_compromise_security = true;
    size_t max_skipped_messages = 2000;
    uint64_t key_rotation_interval = 86400; // 24 hours
    uint64_t handshake_timeout = 30;
    size_t message_buffer_size = 1024;
    bool enable_group_messaging = true;
    size_t max_group_size = 256;
    bool enable_rate_limiting = true;
    size_t max_message_size = MAX_MESSAGE_SIZE;
    uint64_t session_timeout_secs = 3600; // 1 hour
    bool auto_prune_keys = true;
    uint64_t max_key_age_secs = 30 * 86400; // 30 days
};

// Session info struct
struct SessionInfo {
    bytes peer_id;
    size_t messages_sent = 0;
    size_t messages_received = 0;
    std::optional<std::chrono::system_clock::time_point> established_at;
    bool is_established = false;
};

// Group info struct
struct GroupInfo {
    group_id id;
    size_t member_count = 0;
    uint64_t epoch = 0;
    std::optional<std::chrono::system_clock::time_point> created_at;
    std::optional<std::chrono::system_clock::time_point> last_activity;
};

// Safety number comparison result
enum class SafetyComparison {
    MATCH,
    SIMILAR,
    MISMATCH
};

} // namespace sibna
