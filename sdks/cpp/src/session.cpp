#include "sibna/session.hpp"
#include "sibna/context.hpp"
#include "sibna/crypto.hpp"
#include "sibna/x3dh.hpp"

namespace sibna {

// ── Session ──────────────────────────────────────────────────────────────────

Session::Session(bytes peer_id, void* native_handle)
    : session_key_(Utils::random_bytes<KEY_LENGTH>())
    , peer_id_(std::move(peer_id))
    , native_handle_(native_handle)
{}

Session::~Session() {
    Utils::secure_clear(peer_id_);
    Utils::secure_clear(session_key_);
    disposed_ = true;
}

Session::Session(Session&& other) noexcept
    : session_key_(std::move(other.session_key_))
    , ratchet_(std::move(other.ratchet_))
    , ratchet_initialized_(other.ratchet_initialized_)
    , peer_id_(std::move(other.peer_id_))
    , native_handle_(other.native_handle_)
    , disposed_(other.disposed_)
    , messages_sent_(other.messages_sent_)
    , messages_received_(other.messages_received_)
    , established_at_(other.established_at_)
{
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
        ratchet_ = std::move(other.ratchet_);
        ratchet_initialized_ = other.ratchet_initialized_;
        other.native_handle_ = nullptr;
        other.disposed_ = true;
    }
    return *this;
}

Result<void> Session::perform_handshake(const PreKeyBundle& peer_bundle, bool /* initiator */) {
    ensure_not_disposed();

    // Validate the peer bundle
    if (peer_bundle.is_expired()) {
        return Result<void>(ResultCode::INVALID_ARGUMENT, "Peer bundle is expired");
    }

    // Verify the SPK signature before any DH computation
    auto sig_result = peer_bundle.verify_signature(peer_bundle.identity_key());
    if (sig_result.is_err() || !sig_result.value()) {
        return Result<void>(ResultCode::AUTHENTICATION_FAILED, "Bundle signature verification failed");
    }

    // In a full implementation, the caller would:
    // 1. Generate ephemeral X25519 keypair
    // 2. Call x3dh_initiator/x3dh_responder to get shared_secret
    // 3. Derive session keys via x3dh_derive_session_keys
    // 4. Initialize DoubleRatchet from shared secret

    established_at_ = std::chrono::system_clock::now();

    return Result<void>();
}

Result<bytes> Session::encrypt(const bytes& plaintext, const bytes& associated_data) {
    ensure_not_disposed();

    if (plaintext.empty()) {
        return Result<bytes>(ResultCode::INVALID_ARGUMENT, "Plaintext cannot be empty");
    }

    // Use Double Ratchet if initialized
    if (ratchet_initialized_) {
        auto result = ratchet_.ratchet_encrypt(plaintext, associated_data);
        if (result.is_ok()) {
            messages_sent_++;
        }
        return result;
    }

    // Fallback: direct encryption with session key
    auto encrypt_result = Crypto::encrypt(session_key_, plaintext, associated_data);
    if (encrypt_result.is_ok()) {
        messages_sent_++;
    }
    return encrypt_result;
}

Result<bytes> Session::decrypt(const bytes& ciphertext, const bytes& associated_data) {
    ensure_not_disposed();

    if (ciphertext.size() < NONCE_LENGTH + TAG_LENGTH + 1) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Ciphertext too short");
    }

    // Use Double Ratchet if initialized
    if (ratchet_initialized_) {
        auto result = ratchet_.ratchet_decrypt(ciphertext, associated_data);
        if (result.is_ok()) {
            messages_received_++;
        }
        return result;
    }

    // Fallback: direct decryption with session key
    auto decrypt_result = Crypto::decrypt(session_key_, ciphertext, associated_data);
    if (decrypt_result.is_ok()) {
        messages_received_++;
    }
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
