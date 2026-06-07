#include "sibna/context.hpp"
#include "sibna/crypto.hpp"
#include <mutex>
#include <unordered_map>
#include <chrono>

namespace sibna {

// Internal context implementation
struct ContextImpl {
    Config config;
    std::optional<std::string> password;
    std::unordered_map<std::string, std::unique_ptr<Session>> sessions;
    std::unordered_map<std::string, std::unique_ptr<GroupSession>> groups;
    std::optional<IdentityKeyPair> identity;
    std::chrono::system_clock::time_point created_at;
    std::mutex mutex;
    bool disposed = false;
    
    ContextImpl(const Config& cfg, std::optional<std::string> pwd)
        : config(cfg), password(std::move(pwd)), created_at(std::chrono::system_clock::now()) {}
};

// ── Context ──────────────────────────────────────────────────────────────────

Context::Context(void* native_handle, const Config& config)
    : native_handle_(native_handle), config_(config) {
    auto* impl = static_cast<ContextImpl*>(native_handle);
    created_at_ = impl->created_at;
}

Context::~Context() {
    if (native_handle_) {
        auto* impl = static_cast<ContextImpl*>(native_handle_);
        {
            std::lock_guard<std::mutex> lock(impl->mutex);
            // Securely clear all sessions
            for (auto& [id, session] : impl->sessions) {
                session.reset();
            }
            impl->sessions.clear();
            impl->groups.clear();
            impl->disposed = true;
        }
        delete impl;
        native_handle_ = nullptr;
    }
}

Result<std::unique_ptr<Context>> Context::create(
    const Config& config,
    const std::optional<std::string>& password
) {
    try {
        // Validate password if provided
        if (password.has_value()) {
            if (password->length() < 8) {
                return Result<std::unique_ptr<Context>>(ResultCode::INVALID_ARGUMENT,
                    "Password must be at least 8 characters");
            }
        }

        auto* impl = new ContextImpl(config, password);
        
        // Validate config
        if (config.max_skipped_messages > 10000) {
            delete impl;
            return Result<std::unique_ptr<Context>>(ResultCode::INVALID_ARGUMENT,
                "max_skipped_messages too large");
        }
        
        auto context = std::unique_ptr<Context>(new Context(impl, config));
        return context;
    } catch (const std::exception& e) {
        return Result<std::unique_ptr<Context>>(ResultCode::INTERNAL_ERROR, e.what());
    }
}

Result<IdentityKeyPair> Context::generate_identity() {
    ensure_not_disposed();
    auto* impl = static_cast<ContextImpl*>(native_handle_);
    std::lock_guard<std::mutex> lock(impl->mutex);
    
    auto result = IdentityKeyPair::generate();
    if (result.is_ok()) {
        impl->identity = std::move(result).value();
    }
    return result;
}

Result<Session*> Context::create_session(const bytes& peer_id) {
    ensure_not_disposed();
    auto* impl = static_cast<ContextImpl*>(native_handle_);
    std::lock_guard<std::mutex> lock(impl->mutex);
    
    if (peer_id.empty()) {
        return Result<Session*>(ResultCode::INVALID_ARGUMENT,
            "Peer ID cannot be empty");
    }
    
    std::string peer_id_hex = Utils::bytes_to_hex(peer_id);
    
    // Check if session already exists - return existing session
    auto it = impl->sessions.find(peer_id_hex);
    if (it != impl->sessions.end()) {
        return it->second.get();
    }
    
    // Create new session and store it
    auto session = std::make_unique<Session>(peer_id, nullptr);
    auto* session_ptr = session.get();
    impl->sessions[peer_id_hex] = std::move(session);
    
    return session_ptr;
}

Result<bytes> Context::encrypt_message(
    const bytes& peer_id,
    const bytes& plaintext,
    const bytes& associated_data
) {
    ensure_not_disposed();
    auto* impl = static_cast<ContextImpl*>(native_handle_);
    std::lock_guard<std::mutex> lock(impl->mutex);
    
    std::string peer_id_hex = Utils::bytes_to_hex(peer_id);
    auto it = impl->sessions.find(peer_id_hex);
    if (it == impl->sessions.end()) {
        return Result<bytes>(ResultCode::SESSION_NOT_FOUND,
            "No session found for peer: " + peer_id_hex);
    }
    
    return it->second->encrypt(plaintext, associated_data);
}

Result<bytes> Context::decrypt_message(
    const bytes& peer_id,
    const bytes& ciphertext,
    const bytes& associated_data
) {
    ensure_not_disposed();
    auto* impl = static_cast<ContextImpl*>(native_handle_);
    std::lock_guard<std::mutex> lock(impl->mutex);
    
    std::string peer_id_hex = Utils::bytes_to_hex(peer_id);
    auto it = impl->sessions.find(peer_id_hex);
    if (it == impl->sessions.end()) {
        return Result<bytes>(ResultCode::SESSION_NOT_FOUND,
            "No session found for peer: " + peer_id_hex);
    }
    
    return it->second->decrypt(ciphertext, associated_data);
}

Result<GroupSession*> Context::create_group(const group_id& id) {
    ensure_not_disposed();
    auto* impl = static_cast<ContextImpl*>(native_handle_);
    std::lock_guard<std::mutex> lock(impl->mutex);
    
    std::string group_id_hex = Utils::bytes_to_hex(bytes(id.begin(), id.end()));
    
    // Check if group already exists
    if (impl->groups.find(group_id_hex) != impl->groups.end()) {
        return Result<GroupSession*>(ResultCode::INVALID_ARGUMENT,
            "Group already exists");
    }
    
    auto group = std::make_unique<GroupSession>(id);
    auto* group_ptr = group.get();
    impl->groups[group_id_hex] = std::move(group);
    
    return group_ptr;
}

Result<Context::Stats> Context::get_stats() const {
    ensure_not_disposed();
    auto* impl = static_cast<ContextImpl*>(native_handle_);
    std::lock_guard<std::mutex> lock(impl->mutex);
    
    Stats stats;
    stats.session_count = impl->sessions.size();
    stats.group_count = impl->groups.size();
    stats.version = VERSION_STRING;
    stats.created_at = impl->created_at;
    
    return stats;
}

bool Context::is_healthy() const {
    if (!native_handle_) return false;
    
    auto* impl = static_cast<ContextImpl*>(native_handle_);
    std::lock_guard<std::mutex> lock(impl->mutex);
    
    if (impl->disposed) return false;
    
    // Check for stale sessions
    auto now = std::chrono::system_clock::now();
    for (const auto& [id, session] : impl->sessions) {
        if (!session->is_established()) {
            auto age_opt = session->age();
            if (age_opt) {
                auto age_seconds = static_cast<uint64_t>(age_opt->count());
                if (age_seconds > config_.session_timeout_secs) {
                    return false; // Session is stale
                }
            }
        }
    }
    
    (void)now;
    return true;
}

void Context::ensure_not_disposed() const {
    if (!native_handle_) {
        throw SibnaError(ResultCode::INVALID_STATE, "Context has been disposed");
    }
    auto* impl = static_cast<ContextImpl*>(native_handle_);
    std::lock_guard<std::mutex> lock(impl->mutex);
    if (impl->disposed) {
        throw SibnaError(ResultCode::INVALID_STATE, "Context has been disposed");
    }
}

} // namespace sibna
