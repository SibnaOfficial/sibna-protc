#include "sibna/group.hpp"
#include "sibna/crypto.hpp"
#include <algorithm>

namespace sibna {

// ── GroupMessage ─────────────────────────────────────────────────────────────

bytes GroupMessage::to_bytes() const {
    bytes result;
    result.reserve(32 + 4 + 4 + ciphertext.size() + 4 + 8);
    
    // Group ID
    result.insert(result.end(), group_id_.begin(), group_id_.end());
    
    // Sender key ID (4 bytes)
    for (int i = 0; i < 4; ++i) {
        result.push_back(static_cast<byte>((sender_key_id >> (i * 8)) & 0xFF));
    }
    
    // Message number (4 bytes)
    for (int i = 0; i < 4; ++i) {
        result.push_back(static_cast<byte>((message_number >> (i * 8)) & 0xFF));
    }
    
    // Ciphertext length (4 bytes)
    for (int i = 0; i < 4; ++i) {
        result.push_back(static_cast<byte>((ciphertext.size() >> (i * 8)) & 0xFF));
    }
    
    // Ciphertext
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    
    // Epoch (4 bytes)
    for (int i = 0; i < 4; ++i) {
        result.push_back(static_cast<byte>((epoch >> (i * 8)) & 0xFF));
    }
    
    // Timestamp (8 bytes)
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
        timestamp.time_since_epoch()).count();
    for (int i = 0; i < 8; ++i) {
        result.push_back(static_cast<byte>((ts >> (i * 8)) & 0xFF));
    }
    
    return result;
}

Result<GroupMessage> GroupMessage::from_bytes(const bytes& data) {
    if (data.size() < 32 + 4 + 4 + 4 + 4 + 8) {
        return Result<GroupMessage>(ResultCode::INVALID_ARGUMENT, "GroupMessage data too short");
    }
    
    size_t offset = 0;
    
    GroupMessage msg;
    
    // Group ID
    std::copy(data.begin() + offset, data.begin() + offset + 32, msg.group_id_.begin());
    offset += 32;
    
    // Sender key ID
    msg.sender_key_id = 0;
    for (int i = 0; i < 4; ++i) {
        msg.sender_key_id |= static_cast<uint32_t>(data[offset++]) << (i * 8);
    }
    
    // Message number
    msg.message_number = 0;
    for (int i = 0; i < 4; ++i) {
        msg.message_number |= static_cast<uint32_t>(data[offset++]) << (i * 8);
    }
    
    // Ciphertext length
    uint32_t ciphertext_len = 0;
    for (int i = 0; i < 4; ++i) {
        ciphertext_len |= static_cast<uint32_t>(data[offset++]) << (i * 8);
    }
    
    if (data.size() < offset + ciphertext_len + 4 + 8) {
        return Result<GroupMessage>(ResultCode::INVALID_ARGUMENT, "Invalid ciphertext length");
    }
    
    // Ciphertext
    msg.ciphertext.assign(data.begin() + offset, data.begin() + offset + ciphertext_len);
    offset += ciphertext_len;
    
    // Epoch (4 bytes)
    msg.epoch = 0;
    for (int i = 0; i < 4; ++i) {
        msg.epoch |= static_cast<uint32_t>(data[offset++]) << (i * 8);
    }
    
    // Timestamp
    uint64_t ts = 0;
    for (int i = 0; i < 8; ++i) {
        ts |= static_cast<uint64_t>(data[offset++]) << (i * 8);
    }
    msg.timestamp = std::chrono::system_clock::time_point(
        std::chrono::seconds(ts));
    
    return msg;
}

bool GroupMessage::is_expired() const {
    auto age = std::chrono::system_clock::now() - timestamp;
    return age > std::chrono::hours(24);
}

// ── GroupSession ─────────────────────────────────────────────────────────────

GroupSession::GroupSession(group_id id)
    : id_(std::move(id))
    , created_at_(std::chrono::system_clock::now())
    , last_activity_(created_at_)
{}

GroupSession::~GroupSession() {
    // Secure cleanup of sender keys
    for (auto& [member, sender_key] : sender_keys_) {
        Utils::secure_clear(sender_key);
    }
    sender_keys_.clear();
    disposed_ = true;
}

GroupSession::GroupSession(GroupSession&& other) noexcept
    : id_(std::move(other.id_))
    , members_(std::move(other.members_))
    , sender_keys_(std::move(other.sender_keys_))
    , epoch_(other.epoch_)
    , created_at_(other.created_at_)
    , last_activity_(other.last_activity_)
    , disposed_(other.disposed_) {
    other.disposed_ = true;
}

GroupSession& GroupSession::operator=(GroupSession&& other) noexcept {
    if (this != &other) {
        for (auto& [member, sender_key] : sender_keys_) {
            Utils::secure_clear(sender_key);
        }
        id_ = std::move(other.id_);
        members_ = std::move(other.members_);
        sender_keys_ = std::move(other.sender_keys_);
        epoch_ = other.epoch_;
        created_at_ = other.created_at_;
        last_activity_ = other.last_activity_;
        disposed_ = other.disposed_;
        other.disposed_ = true;
    }
    return *this;
}

Result<void> GroupSession::add_member(const std::array<byte, 32>& public_key) {
    ensure_not_disposed();
    
    if (members_.size() >= MAX_GROUP_SIZE) {
        return Result<void>(ResultCode::INVALID_ARGUMENT, "Group is full");
    }
    
    // Check if member already exists
    auto it = std::find(members_.begin(), members_.end(), public_key);
    if (it != members_.end()) {
        return Result<void>(ResultCode::INVALID_ARGUMENT, "Member already in group");
    }
    
    members_.push_back(public_key);
    touch();
    
    return Result<void>();
}

Result<void> GroupSession::remove_member(const std::array<byte, 32>& public_key) {
    ensure_not_disposed();
    
    auto it = std::find(members_.begin(), members_.end(), public_key);
    if (it == members_.end()) {
        return Result<void>(ResultCode::KEY_NOT_FOUND, "Member not in group");
    }
    
    members_.erase(it);
    
    // Remove sender key for this member
    std::string pk_hex = Utils::bytes_to_hex(bytes(public_key.begin(), public_key.end()));
    auto sk_it = sender_keys_.find(pk_hex);
    if (sk_it != sender_keys_.end()) {
        Utils::secure_clear(sk_it->second);
        sender_keys_.erase(sk_it);
    }
    
    // Increment epoch for membership change
    epoch_++;
    touch();
    
    return Result<void>();
}

Result<void> GroupSession::import_sender_key(
    const std::array<byte, 32>& member_public_key,
    const key& sender_key
) {
    ensure_not_disposed();
    
    std::string pk_hex = Utils::bytes_to_hex(bytes(member_public_key.begin(), member_public_key.end()));
    sender_keys_[pk_hex] = sender_key;
    touch();
    
    return Result<void>();
}

Result<GroupMessage> GroupSession::encrypt(const bytes& plaintext) {
    ensure_not_disposed();
    
    if (members_.empty()) {
        return Result<GroupMessage>(ResultCode::INVALID_STATE, "No members in group");
    }
    
    // Generate a sender key for this message
    auto key_result = Crypto::generate_key();
    if (key_result.is_err()) {
        return Result<GroupMessage>(key_result.code(), key_result.message());
    }
    
    // Encrypt the plaintext
    auto encrypt_result = Crypto::encrypt(key_result.value(), plaintext);
    if (encrypt_result.is_err()) {
        return Result<GroupMessage>(encrypt_result.code(), encrypt_result.message());
    }
    
    GroupMessage msg;
    msg.group_id_ = id_;
    msg.sender_key_id = static_cast<uint32_t>(epoch_);
    msg.message_number = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    msg.ciphertext = encrypt_result.value();
    msg.epoch = epoch_;
    msg.timestamp = std::chrono::system_clock::now();
    
    touch();
    return msg;
}

Result<bytes> GroupSession::decrypt(
    const GroupMessage& message,
    const std::array<byte, 32>& sender_public_key
) {
    ensure_not_disposed();
    
    if (message.is_expired()) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Message is expired");
    }
    
    if (message.group_id_ != id_) {
        return Result<bytes>(ResultCode::INVALID_ARGUMENT, "Message belongs to different group");
    }
    
    // Find the sender key
    std::string pk_hex = Utils::bytes_to_hex(bytes(sender_public_key.begin(), sender_public_key.end()));
    auto it = sender_keys_.find(pk_hex);
    if (it == sender_keys_.end()) {
        return Result<bytes>(ResultCode::KEY_NOT_FOUND, "No sender key for this member");
    }
    
    // Decrypt
    auto decrypt_result = Crypto::decrypt(it->second, message.ciphertext);
    if (decrypt_result.is_ok()) {
        touch();
    }
    
    return decrypt_result;
}

Result<void> GroupSession::leave() {
    ensure_not_disposed();
    
    // Clear all sender keys
    for (auto& [member, sender_key] : sender_keys_) {
        Utils::secure_clear(sender_key);
    }
    sender_keys_.clear();
    members_.clear();
    epoch_++;
    
    return Result<void>();
}

GroupInfo GroupSession::get_info() const {
    GroupInfo info;
    info.id = id_;
    info.member_count = members_.size();
    info.epoch = epoch_;
    info.created_at = created_at_;
    info.last_activity = last_activity_;
    return info;
}

void GroupSession::touch() {
    last_activity_ = std::chrono::system_clock::now();
}

void GroupSession::ensure_not_disposed() const {
    if (disposed_) {
        throw SibnaError(ResultCode::INVALID_STATE, "GroupSession has been disposed");
    }
}

} // namespace sibna
