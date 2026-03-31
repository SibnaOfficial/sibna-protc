#pragma once

#include "types.hpp"
#include <stdexcept>
#include <string>

namespace sibna {

// Base exception class
class SibnaError : public std::runtime_error {
public:
    explicit SibnaError(ResultCode code)
        : std::runtime_error(code_to_string(code)), code_(code) {}
    
    SibnaError(ResultCode code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    ResultCode code() const { return code_; }
    
    bool is_security_error() const {
        return code_ == ResultCode::INVALID_KEY ||
               code_ == ResultCode::AUTHENTICATION_FAILED ||
               code_ == ResultCode::INVALID_CIPHERTEXT;
    }

    bool is_recoverable() const {
        return code_ == ResultCode::RATE_LIMIT_EXCEEDED ||
               code_ == ResultCode::BUFFER_TOO_SMALL;
    }

    bool is_fatal() const {
        return code_ == ResultCode::OUT_OF_MEMORY ||
               code_ == ResultCode::INTERNAL_ERROR;
    }

private:
    static std::string code_to_string(ResultCode code) {
        switch (code) {
            case ResultCode::OK: return "Success";
            case ResultCode::INVALID_ARGUMENT: return "Invalid argument";
            case ResultCode::INVALID_KEY: return "Invalid key";
            case ResultCode::ENCRYPTION_FAILED: return "Encryption failed";
            case ResultCode::DECRYPTION_FAILED: return "Decryption failed";
            case ResultCode::OUT_OF_MEMORY: return "Out of memory";
            case ResultCode::INVALID_STATE: return "Invalid state";
            case ResultCode::SESSION_NOT_FOUND: return "Session not found";
            case ResultCode::KEY_NOT_FOUND: return "Key not found";
            case ResultCode::RATE_LIMIT_EXCEEDED: return "Rate limit exceeded";
            case ResultCode::INTERNAL_ERROR: return "Internal error";
            case ResultCode::BUFFER_TOO_SMALL: return "Buffer too small";
            case ResultCode::INVALID_CIPHERTEXT: return "Invalid ciphertext";
            case ResultCode::AUTHENTICATION_FAILED: return "Authentication failed";
            case ResultCode::NOT_INITIALIZED: return "Not initialized";
            default: return "Unknown error";
        }
    }

    ResultCode code_;
};

// Validation error
class ValidationError : public SibnaError {
public:
    ValidationError(const std::string& field, const std::string& message)
        : SibnaError(ResultCode::INVALID_ARGUMENT, message), field_(field) {}

    const std::string& field() const { return field_; }

private:
    std::string field_;
};

// Crypto error
class CryptoError : public SibnaError {
public:
    explicit CryptoError(ResultCode code) : SibnaError(code) {}
    CryptoError(ResultCode code, const std::string& message) : SibnaError(code, message) {}
};

// Session error
class SessionError : public SibnaError {
public:
    explicit SessionError(ResultCode code) : SibnaError(code) {}
    SessionError(ResultCode code, const std::string& message) : SibnaError(code, message) {}
};

// Group error
class GroupError : public SibnaError {
public:
    explicit GroupError(ResultCode code) : SibnaError(code) {}
    GroupError(ResultCode code, const std::string& message) : SibnaError(code, message) {}
};

// Helper macro for checking results
#define SIBNA_CHECK_RESULT(expr) \
    do { \
        auto _result = (expr); \
        if (_result.is_err()) { \
            throw SibnaError(_result.code(), _result.message()); \
        } \
    } while (0)

// Helper macro for checking and returning results
#define SIBNA_TRY(expr) \
    do { \
        auto _result = (expr); \
        if (_result.is_err()) { \
            return _result; \
        } \
    } while (0)

} // namespace sibna
