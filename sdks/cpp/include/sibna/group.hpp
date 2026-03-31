#pragma once

#include "types.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace sibna {

// Group message structure
struct GroupMessage {
    group_id group_id;
    uint32_t sender_key_id;
    uint32_t message_number;
    bytes ciphertext;
    uint64_t epoch;
    std::chrono::system_clock::time_point timestamp;

    // Serialize to bytes
    bytes to_bytes() const;

    // Deserialize from bytes
    static Result<GroupMessage> from_bytes(const bytes& data);

    // Check if expired (older than 24 hours)
    bool is_expired() const;
};

// Group session for group messaging
class GroupSession {
public:
    // Create a new group session
    explicit GroupSession(group_id id);

    // Destructor
    ~GroupSession();

    // Disable copy
    GroupSession(const GroupSession&) = delete;
    GroupSession& operator=(const GroupSession&) = delete;

    // Enable move
    GroupSession(GroupSession&& other) noexcept;
    GroupSession& operator=(GroupSession&& other) noexcept;

    // Get group ID
    const group_id& id() const { return id_; }

    // Get current epoch
    uint64_t epoch() const { return epoch_; }

    // Get member count
    size_t member_count() const { return members_.size(); }

    // Get members
    const std::vector<std::array<byte, 32>>& members() const { return members_; }

    // Add a member
    Result<void> add_member(const std::array<byte, 32>& public_key);

    // Remove a member
    Result<void> remove_member(const std::array<byte, 32>& public_key);

    // Import a sender key from a member
    Result<void> import_sender_key(
        const std::array<byte, 32>& member_public_key,
        const key& sender_key
    );

    // Encrypt a group message
    Result<GroupMessage> encrypt(const bytes& plaintext);

    // Decrypt a group message
    Result<bytes> decrypt(
        const GroupMessage& message,
        const std::array<byte, 32>& sender_public_key
    );

    // Leave the group
    Result<void> leave();

    // Get group statistics
    GroupInfo get_info() const;

private:
    group_id id_;
    std::vector<std::array<byte, 32>> members_;
    std::map<std::string, key> sender_keys_;
    uint64_t epoch_ = 0;
    std::optional<std::chrono::system_clock::time_point> created_at_;
    std::optional<std::chrono::system_clock::time_point> last_activity_;
    bool disposed_ = false;

    void touch();
    void ensure_not_disposed() const;
};

} // namespace sibna
