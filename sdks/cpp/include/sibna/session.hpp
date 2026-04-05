#pragma once

#include "types.hpp"
#include "error.hpp"
#include "identity.hpp"
#include "utils.hpp"

namespace sibna {

// Forward declaration
class Context;

// Secure session for encrypted communication
class Session {
public:
    // Destructor
    ~Session();

    // Disable copy
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Enable move
    Session(Session&& other) noexcept;
    Session& operator=(Session&& other) noexcept;

    // Perform X3DH handshake
    Result<void> perform_handshake(
        const PreKeyBundle& peer_bundle,
        bool initiator
    );

    // Encrypt a message
    Result<bytes> encrypt(
        const bytes& plaintext,
        const bytes& associated_data = {}
    );

    // Decrypt a message
    Result<bytes> decrypt(
        const bytes& ciphertext,
        const bytes& associated_data = {}
    );

    // Get peer ID
    const bytes& peer_id() const { return peer_id_; }

    // Get current message number
    size_t current_message_number() const;

    // Check if session is established
    bool is_established() const;

    // Get session age
    std::optional<std::chrono::seconds> age() const;

    // Get session statistics
    SessionInfo get_stats() const;

private:
    // Private constructor - only Context can create sessions
    Session(bytes peer_id, void* native_handle);

    friend class Context;

    bytes peer_id_;
    void* native_handle_;
    bool disposed_ = false;
    size_t messages_sent_ = 0;
    size_t messages_received_ = 0;
    std::optional<std::chrono::system_clock::time_point> established_at_;

    void ensure_not_disposed() const;
};

} // namespace sibna
