#include "sibna/session.hpp"
#include "sibna/context.hpp"
#include "sibna/crypto.hpp"

namespace sibna {

// ── Session ──────────────────────────────────────────────────────────────────

Session::Session(bytes peer_id, void* native_handle)
    : peer_id_(std::move(peer_id))
    , native_handle_(native_handle)
    , established_at_(std::chrono::system_clock::now())
    , session_key_(Utils::random_bytes<KEY_LENGTH>())
{}

Session::~Session() {
    // Secure cleanup
    Utils::secure_clear(peer_id_);
    Utils::secure_clear(session_key_);
    disposed_ = true;
}

Session::Session(Session&& other) noexcept
    : peer_id_(std::move(other.peer_id_))
    , native_handle_(other.native_handle_)
    , disposed_(other.disposed_)
    , messages_sent_(other.messages_sent_)
    , messages_received_(other.messages_received_)
    , established_at_(other.established_at_)
    , session_key_(std::move(other.session_key_)) {
    other.native_handle_ = nullptr;
    other.disposed_ = true;
}

Session& Session::operator=(Session&& other) noexcept {
    if (this != &other) {
        Utils::secure_clear(peer_id_);
        Utils::secure_clear(session_key_);
        peer_id_ = std::move(other.peer_id_);
        native_handle_ = other.native_handle_;
        disposed_ = other.disposed_;
        messages_sent_ = other.messages_sent_;
        messages_received_ = other.messages_received_;
        established_at_ = other.established_at_;
        session_key_ = std::move(other.session_key_);
        other.native_handle_ = nullptr;
        other.disposed_ = true;
    }
    return *this;
}

Result<void> Session::perform_handshake(const PreKeyBundle& peer_bundle, bool initiator) {
    ensure_not_disposed();
    
    // Validate the peer bundle
    if (peer_bundle.is_expired()) {
        return Result<void>(ResultCode::INVALID_ARGUMENT, "Peer bundle is expired");
    }
    
    // Verify the bundle signature
    auto sig_result = peer_bundle.verify_signature(peer_bundle.identity_key());
    if (sig_result.is_err() || !sig_result.value()) {
        return Result<void>(ResultCode::AUTHENTICATION_FAILED, "Bundle signature verification failed");
    }
    
    // Perform X3DH handshake using the session key
    // The session_key_ is already set in the constructor
    // In a full implementation, this would derive the key from X3DH DH operations
    
    established_at_ = std::chrono::system_clock::now();
    
    return Result<void>();
}

Result<bytes> Session::encrypt(const bytes& plaintext, const bytes& associated_data) {
    ensure_not_disposed();
    
    if (plaintext.empty()) {
        return Result<bytes>(ResultCode::INVALID_ARGUMENT, "Plaintext cannot be empty");
    }
    
    // Encrypt using the session key
    auto encrypt_result = Crypto::encrypt(session_key_, plaintext, associated_data);
    if (encrypt_result.is_err()) {
        return encrypt_result;
    }
    
    messages_sent_++;
    
    return encrypt_result;
}

Result<bytes> Session::decrypt(const bytes& ciphertext, const bytes& associated_data) {
    ensure_not_disposed();
    
    if (ciphertext.size() < NONCE_LENGTH + TAG_LENGTH + 1) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Ciphertext too short");
    }
    
    // Decrypt using the session key
    auto decrypt_result = Crypto::decrypt(session_key_, ciphertext, associated_data);
    if (decrypt_result.is_err()) {
        return decrypt_result;
    }
    
    messages_received_++;
    
    return decrypt_result;
}

size_t Session::current_message_number() const {
    return messages_sent_;
}

bool Session::is_established() const {
    return established_at_.has_value();
}

std::optional<std::chrono::seconds> Session::age() const {
    if (!established_at_) {
        return std::nullopt;
    }
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - *established_at_);
}

SessionInfo Session::get_stats() const {
    SessionInfo info;
    info.peer_id = peer_id_;
    info.messages_sent = messages_sent_;
    info.messages_received = messages_received_;
    info.established_at = established_at_;
    info.is_established = established_at_.has_value();
    return info;
}

void Session::ensure_not_disposed() const {
    if (disposed_) {
        throw SibnaError(ResultCode::INVALID_STATE, "Session has been disposed");
    }
}

} // namespace sibna
