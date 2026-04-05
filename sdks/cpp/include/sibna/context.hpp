#pragma once

#include "types.hpp"
#include "error.hpp"
#include "identity.hpp"
#include "session.hpp"
#include "group.hpp"
#include "utils.hpp"

namespace sibna {

// Secure context for Sibna protocol operations
class Context {
public:
    // Create a new secure context
    static Result<std::unique_ptr<Context>> create(
        const Config& config = Config{},
        const std::optional<std::string>& password = std::nullopt
    );

    // Destructor
    ~Context();

    // Disable copy
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    // Disable move (sessions hold references)
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;

    // Generate a new identity key pair
    Result<IdentityKeyPair> generate_identity();

    // Create a new session with a peer
    Result<std::unique_ptr<Session>> create_session(const bytes& peer_id);

    // Encrypt a message for a session
    Result<bytes> encrypt_message(
        const bytes& peer_id,
        const bytes& plaintext,
        const bytes& associated_data = {}
    );

    // Decrypt a message from a session
    Result<bytes> decrypt_message(
        const bytes& peer_id,
        const bytes& ciphertext,
        const bytes& associated_data = {}
    );

    // Create a new group
    Result<std::unique_ptr<GroupSession>> create_group(const group_id& id);

    // Get context statistics
    struct Stats {
        size_t session_count;
        size_t group_count;
        std::string version;
        std::chrono::system_clock::time_point created_at;
    };
    Result<Stats> get_stats() const;

    // Check if healthy
    bool is_healthy() const;

private:
    // Private constructor
    explicit Context(void* native_handle, const Config& config);

    void* native_handle_;
    Config config_;
    bool disposed_ = false;
    std::chrono::system_clock::time_point created_at_;

    void ensure_not_disposed() const;
};

} // namespace sibna
