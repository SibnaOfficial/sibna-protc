#pragma once

#include "types.hpp"
#include "error.hpp"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace sibna {

// Utility functions
class Utils {
public:
    // Delete constructor - static class
    Utils() = delete;

    // Convert bytes to hex string
    static std::string bytes_to_hex(const bytes& data) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (const auto& byte : data) {
            oss << std::setw(2) << static_cast<int>(byte);
        }
        return oss.str();
    }

    // Convert hex string to bytes
    static bytes hex_to_bytes(const std::string& hex) {
        if (hex.length() % 2 != 0) {
            throw ValidationError("hex", "Invalid hex string length");
        }

        bytes result;
        result.reserve(hex.length() / 2);

        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byte_string = hex.substr(i, 2);
            result.push_back(static_cast<byte>(std::stoi(byte_string, nullptr, 16)));
        }

        return result;
    }

    // Convert bytes to base64 string
    static std::string bytes_to_base64(const bytes& data);
    
    // Convert base64 string to bytes
    static bytes base64_to_bytes(const std::string& base64);

    // Constant-time comparison
    static bool constant_time_equals(const bytes& a, const bytes& b) {
        if (a.size() != b.size()) {
            return false;
        }

        byte result = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    // Constant-time comparison for fixed-size arrays
    template<size_t N>
    static bool constant_time_equals(const std::array<byte, N>& a, 
                                      const std::array<byte, N>& b) {
        byte result = 0;
        for (size_t i = 0; i < N; ++i) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    // Check if all zeros
    static bool is_all_zeros(const bytes& data) {
        for (const auto& b : data) {
            if (b != 0) return false;
        }
        return true;
    }

    template<size_t N>
    static bool is_all_zeros(const std::array<byte, N>& data) {
        for (const auto& b : data) {
            if (b != 0) return false;
        }
        return true;
    }

    // Securely clear memory
    static void secure_clear(bytes& data) {
        std::fill(data.begin(), data.end(), 0);
    }

    template<size_t N>
    static void secure_clear(std::array<byte, N>& data) {
        data.fill(0);
    }

    // Securely clear and delete
    template<typename T>
    static void secure_delete(T* ptr) {
        if (ptr) {
            std::fill_n(reinterpret_cast<byte*>(ptr), sizeof(T), 0);
            delete ptr;
        }
    }

    // Generate random bytes
    static bytes random_bytes(size_t length) {
        static thread_local std::random_device rd;
        static thread_local std::mt19937 gen(rd());
        static thread_local std::uniform_int_distribution<> dis(0, 255);

        bytes result(length);
        for (auto& b : result) {
            b = static_cast<byte>(dis(gen));
        }
        return result;
    }

    template<size_t N>
    static std::array<byte, N> random_bytes() {
        static thread_local std::random_device rd;
        static thread_local std::mt19937 gen(rd());
        static thread_local std::uniform_int_distribution<> dis(0, 255);

        std::array<byte, N> result;
        for (auto& b : result) {
            b = static_cast<byte>(dis(gen));
        }
        return result;
    }

    // Validate key length
    static void validate_key_length(const bytes& key, size_t expected = KEY_LENGTH) {
        if (key.size() != expected) {
            throw ValidationError("key", 
                "Invalid key length: expected " + std::to_string(expected) + 
                ", got " + std::to_string(key.size()));
        }
    }

    template<size_t N>
    static void validate_key_length(const std::array<byte, N>&) {
        // Fixed-size array is always valid
    }

    // Validate message size
    static void validate_message_size(const bytes& message, size_t max_size = MAX_MESSAGE_SIZE) {
        if (message.empty()) {
            throw ValidationError("message", "Message cannot be empty");
        }
        if (message.size() > max_size) {
            throw ValidationError("message", 
                "Message too large: " + std::to_string(message.size()) + 
                " > " + std::to_string(max_size));
        }
    }

    // Validate timestamp
    static void validate_timestamp(uint64_t timestamp, uint64_t max_age_seconds = 300) {
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        auto age = now - static_cast<int64_t>(timestamp);

        if (timestamp > static_cast<uint64_t>(now + 60)) {
            throw ValidationError("timestamp", "Timestamp is in the future");
        }

        if (age > static_cast<int64_t>(max_age_seconds)) {
            throw ValidationError("timestamp", "Timestamp is too old");
        }
    }

    // Concatenate byte arrays
    template<typename... Args>
    static bytes concat(const Args&... args) {
        bytes result;
        result.reserve((args.size() + ...));
        (result.insert(result.end(), args.begin(), args.end()), ...);
        return result;
    }

    // XOR two byte arrays
    static bytes xor_bytes(const bytes& a, const bytes& b) {
        if (a.size() != b.size()) {
            throw std::invalid_argument("Arrays must have the same length");
        }

        bytes result(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    // Calculate fingerprint
    static std::string calculate_fingerprint(const bytes& public_key);

    // Format safety number
    static std::string format_safety_number(const std::string& safety_number);

    // Compare byte arrays lexicographically
    template<size_t N>
    static int compare_bytes(const std::array<byte, N>& a, const std::array<byte, N>& b) {
        for (size_t i = 0; i < N; ++i) {
            if (a[i] != b[i]) {
                return static_cast<int>(a[i]) - static_cast<int>(b[i]);
            }
        }
        return 0;
    }
};

// Secure buffer class
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size) : data_(size) {}
    explicit SecureBuffer(bytes data) : data_(std::move(data)) {}

    ~SecureBuffer() {
        clear();
    }

    // Disable copy
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Enable move
    SecureBuffer(SecureBuffer&& other) noexcept 
        : data_(std::move(other.data_)) {}
    
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    byte* data() { return data_.data(); }
    const byte* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    bytes& get() { return data_; }
    const bytes& get() const { return data_; }

    void resize(size_t new_size) {
        // Zeroize old data before resizing
        if (new_size < data_.size()) {
            std::fill(data_.begin() + new_size, data_.end(), 0);
        }
        data_.resize(new_size);
    }

    void clear() {
        Utils::secure_clear(data_);
        data_.clear();
    }

    bytes release() {
        bytes result = std::move(data_);
        data_.clear();
        return result;
    }

private:
    bytes data_;
};

} // namespace sibna
