#include "sibna/double_ratchet.hpp"
#include "sibna/crypto.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring>

namespace sibna {

/// Convert bytes to key (array). Copies up to KEY_LENGTH bytes, zero-pads.
static key bytes_to_key(const bytes& b) {
    key result{};
    size_t len = std::min(b.size(), size_t(KEY_LENGTH));
    std::copy(b.begin(), b.begin() + len, result.begin());
    return result;
}

/// Convert key to bytes vector
static bytes key_to_bytes(const key& k) {
    return bytes(k.begin(), k.end());
}

// ── ChainKey ─────────────────────────────────────────────────────────────────

ChainKey::ChainKey() {
    chain_key.fill(0);
    auto now = std::chrono::system_clock::now().time_since_epoch();
    created_at = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

ChainKey::ChainKey(const key& k) : chain_key(k) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    created_at = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

ChainKey::ChainKey(const key& k, uint64_t idx) : chain_key(k), index(idx) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    created_at = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

std::optional<std::pair<key, ChainKey>> ChainKey::next_message_key() {
    if (index >= max_messages) {
        return std::nullopt;
    }

    // Message key = HMAC-SHA256(chain_key, 0x01)
    bytes mk_seed = {MESSAGE_KEY_SEED};
    auto mk_result = Crypto::hmac_sha256(chain_key, mk_seed);
    if (mk_result.is_err()) return std::nullopt;
    key message_key = bytes_to_key(mk_result.value());

    // Next chain key = HMAC-SHA256(chain_key, 0x02)
    bytes ck_seed = {CHAIN_KEY_SEED};
    auto ck_result = Crypto::hmac_sha256(chain_key, ck_seed);
    if (ck_result.is_err()) return std::nullopt;
    key next_ck = bytes_to_key(ck_result.value());

    ChainKey next(next_ck, index + 1);
    next.created_at = created_at;
    next.max_messages = max_messages;

    return std::make_pair(message_key, next);
}

key ChainKey::derive_header_key() const {
    bytes seed = {HEADER_KEY_SEED};
    auto result = Crypto::hmac_sha256(chain_key, seed);
    if (result.is_err()) return key{};
    return bytes_to_key(result.value());
}

uint64_t ChainKey::remaining_messages() const {
    return (index < max_messages) ? (max_messages - index) : 0;
}

bool ChainKey::needs_rotation() const {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    uint64_t now_secs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
    return index >= max_messages || (now_secs - created_at) > 86400;
}

// ── RatchetHeader ────────────────────────────────────────────────────────────

bytes RatchetHeader::to_bytes() const {
    bytes out;
    out.reserve(HEADER_SIZE);
    out.insert(out.end(), dh_public.begin(), dh_public.end());
    // message_number: 4 bytes LE
    out.push_back(static_cast<byte>(message_number & 0xFF));
    out.push_back(static_cast<byte>((message_number >> 8) & 0xFF));
    out.push_back(static_cast<byte>((message_number >> 16) & 0xFF));
    out.push_back(static_cast<byte>((message_number >> 24) & 0xFF));
    // previous_chain_length: 4 bytes LE
    out.push_back(static_cast<byte>(previous_chain_length & 0xFF));
    out.push_back(static_cast<byte>((previous_chain_length >> 8) & 0xFF));
    out.push_back(static_cast<byte>((previous_chain_length >> 16) & 0xFF));
    out.push_back(static_cast<byte>((previous_chain_length >> 24) & 0xFF));
    return out;
}

Result<RatchetHeader> RatchetHeader::from_bytes(const bytes& data) {
    if (data.size() < HEADER_SIZE) {
        return Result<RatchetHeader>(ResultCode::INVALID_CIPHERTEXT, "Header too short");
    }

    RatchetHeader h;
    std::copy(data.begin(), data.begin() + 32, h.dh_public.begin());

    h.message_number = static_cast<uint32_t>(data[32])
                     | (static_cast<uint32_t>(data[33]) << 8)
                     | (static_cast<uint32_t>(data[34]) << 16)
                     | (static_cast<uint32_t>(data[35]) << 24);

    h.previous_chain_length = static_cast<uint32_t>(data[36])
                            | (static_cast<uint32_t>(data[37]) << 8)
                            | (static_cast<uint32_t>(data[38]) << 16)
                            | (static_cast<uint32_t>(data[39]) << 24);

    return h;
}

Result<void> RatchetHeader::validate() const {
    if (Utils::is_all_zeros(dh_public)) {
        return Result<void>(ResultCode::INVALID_CIPHERTEXT, "DH public key is all zeros");
    }
    return Result<void>();
}

// ── DoubleRatchet ────────────────────────────────────────────────────────────

DoubleRatchet::DoubleRatchet() {
    root_key.fill(0);
    dh_local_private.fill(0);
    dh_local_public.fill(0);
    dh_remote_public.fill(0);
}

DoubleRatchet DoubleRatchet::from_shared_secret(
    const key& shared_secret,
    const key& local_dh_private,
    const key& remote_dh_public,
    bool role_is_initiator
) {
    DoubleRatchet dr;

    // HKDF(shared_secret, salt="SibnaSession_v3",
    //       info="SibnaRootAndChainKey_v3", length=64)
    bytes salt = {'S','i','b','n','a','S','e','s','s','i','o','n','_','v','3'};
    bytes info = {'S','i','b','n','a','R','o','o','t','A','n','d','C','h','a','i','n','K','e','y','_','v','3'};

    // HKDF-Extract
    key salt_key{};
    std::copy(salt.begin(), salt.end(), salt_key.begin());
    auto prk = Crypto::hmac_sha256(salt_key, key_to_bytes(shared_secret));

    // HKDF-Expand to 64 bytes
    bytes prev;
    bytes okm(64);

    // T(1)
    bytes t1_in;
    t1_in.insert(t1_in.end(), prev.begin(), prev.end());
    t1_in.insert(t1_in.end(), info.begin(), info.end());
    t1_in.push_back(1);
    auto t1 = Crypto::hmac_sha256(bytes_to_key(prk.value()), t1_in);
    std::copy(t1.value().begin(), t1.value().begin() + 32, okm.begin());
    prev = t1.value();

    // T(2)
    bytes t2_in;
    t2_in.insert(t2_in.end(), prev.begin(), prev.end());
    t2_in.insert(t2_in.end(), info.begin(), info.end());
    t2_in.push_back(2);
    auto t2 = Crypto::hmac_sha256(bytes_to_key(prk.value()), t2_in);
    std::copy(t2.value().begin(), t2.value().begin() + 32, okm.begin() + 32);

    std::copy(okm.begin(), okm.begin() + 32, dr.root_key.begin());
    key chain_key_bytes;
    std::copy(okm.begin() + 32, okm.end(), chain_key_bytes.begin());

    dr.dh_local_private = local_dh_private;
    auto pub_result = X25519::generate_keypair_from_private(local_dh_private);
    if (pub_result.is_ok()) {
        dr.dh_local_public = pub_result.value().second;
    }
    dr.dh_remote_public = remote_dh_public;

    if (role_is_initiator) {
        dr.sending_chain = ChainKey(chain_key_bytes);
    } else {
        dr.receiving_chain = ChainKey(chain_key_bytes);
    }

    return dr;
}

// ── Root Key KDF ─────────────────────────────────────────────────────────────

std::pair<key, key> DoubleRatchet::kdf_rk(const key& dh_out) {
    // HKDF(salt=root_key, ikm=dh_out, info="SibnaRatchet_v3", length=64)
    bytes info = {'S','i','b','n','a','R','a','t','c','h','e','t','_','v','3'};

    // HKDF-Extract: PRK = HMAC-Hash(root_key, dh_out)
    auto prk = Crypto::hmac_sha256(root_key, key_to_bytes(dh_out));

    // HKDF-Expand to 64 bytes
    bytes prev;
    bytes okm(64);

    bytes t1_in;
    t1_in.insert(t1_in.end(), prev.begin(), prev.end());
    t1_in.insert(t1_in.end(), info.begin(), info.end());
    t1_in.push_back(1);
    auto t1 = Crypto::hmac_sha256(bytes_to_key(prk.value()), t1_in);
    std::copy(t1.value().begin(), t1.value().begin() + 32, okm.begin());
    prev = t1.value();

    bytes t2_in;
    t2_in.insert(t2_in.end(), prev.begin(), prev.end());
    t2_in.insert(t2_in.end(), info.begin(), info.end());
    t2_in.push_back(2);
    auto t2 = Crypto::hmac_sha256(bytes_to_key(prk.value()), t2_in);
    std::copy(t2.value().begin(), t2.value().begin() + 32, okm.begin() + 32);

    key new_rk, new_ck;
    std::copy(okm.begin(), okm.begin() + 32, new_rk.begin());
    std::copy(okm.begin() + 32, okm.end(), new_ck.begin());

    return std::make_pair(new_rk, new_ck);
}

// ── DH Ratchet Step ─────────────────────────────────────────────────────────

void DoubleRatchet::dh_ratchet_step() {
    // Receive step: use EXISTING local key to DH with new remote key
    auto dh_out_recv_result = X25519::diffie_hellman(dh_local_private, dh_remote_public);
    if (dh_out_recv_result.is_ok()) {
        auto [new_rk, receiving_chain_key] = kdf_rk(dh_out_recv_result.value());
        root_key = new_rk;
        receiving_chain = ChainKey(receiving_chain_key);
    }

    // Send step: generate new local key pair
    auto new_kp = X25519::generate_keypair();
    if (new_kp.is_ok()) {
        dh_local_private = new_kp.value().first;
        dh_local_public = new_kp.value().second;

        auto dh_out_send_result = X25519::diffie_hellman(dh_local_private, dh_remote_public);
        if (dh_out_send_result.is_ok()) {
            auto [new_rk2, sending_chain_key] = kdf_rk(dh_out_send_result.value());
            root_key = new_rk2;
            sending_chain = ChainKey(sending_chain_key);
        }
    }
}

void DoubleRatchet::perform_send_ratchet() {
    if (Utils::is_all_zeros(dh_remote_public)) return;

    auto new_kp = X25519::generate_keypair();
    if (new_kp.is_ok()) {
        dh_local_private = new_kp.value().first;
        dh_local_public = new_kp.value().second;

        auto dh_out_result = X25519::diffie_hellman(dh_local_private, dh_remote_public);
        if (dh_out_result.is_ok()) {
            auto [new_rk, sending_chain_key] = kdf_rk(dh_out_result.value());
            root_key = new_rk;
            sending_chain = ChainKey(sending_chain_key);
        }
    }
}

// ── Skip Message Keys ────────────────────────────────────────────────────────

Result<void> DoubleRatchet::skip_message_keys(uint32_t until) {
    if (!receiving_chain.has_value()) {
        return Result<void>();
    }

    if (until > receiving_chain->index + max_skip) {
        return Result<void>(ResultCode::INVALID_CIPHERTEXT, "Too many skipped messages");
    }

    while (receiving_chain->index < until) {
        auto result = receiving_chain->next_message_key();
        if (!result.has_value()) {
            break;
        }
        auto [mk, next_ck] = *result;
        uint32_t key_index = static_cast<uint32_t>(receiving_chain->index);

        // Store skipped key
        bytes pub_key(dh_remote_public.begin(), dh_remote_public.end());
        skipped_keys[{pub_key, key_index}] = mk;

        if (skipped_keys.size() > max_skip) {
            // Evict oldest
            auto it = skipped_keys.begin();
            if (it != skipped_keys.end()) {
                skipped_keys.erase(it);
            }
        }

        receiving_chain = next_ck;
    }

    return Result<void>();
}

std::optional<key> DoubleRatchet::try_skipped_key(const key& dh_public, uint32_t msg_num) {
    bytes pub(dh_public.begin(), dh_public.end());
    auto it = skipped_keys.find({pub, msg_num});
    if (it != skipped_keys.end()) {
        key mk = it->second;
        skipped_keys.erase(it);
        return mk;
    }
    return std::nullopt;
}

void DoubleRatchet::clear_skipped_keys() {
    for (auto& [k, v] : skipped_keys) {
        v.fill(0);
    }
    skipped_keys.clear();
}

// ── Encrypt ──────────────────────────────────────────────────────────────────

Result<bytes> DoubleRatchet::ratchet_encrypt(
    const bytes& plaintext,
    const bytes& associated_data
) {
    // If no sending chain, do a DH ratchet step to create one
    if (!sending_chain.has_value()) {
        if (Utils::is_all_zeros(dh_remote_public)) {
            return Result<bytes>(ResultCode::INVALID_STATE, "No remote DH public key");
        }
        perform_send_ratchet();
    }

    if (!sending_chain.has_value()) {
        return Result<bytes>(ResultCode::INVALID_STATE, "Failed to create sending chain");
    }

    // Capture msg_num BEFORE advancing the chain
    uint32_t msg_num = static_cast<uint32_t>(sending_chain->index);

    auto result = sending_chain->next_message_key();
    if (!result.has_value()) {
        return Result<bytes>(ResultCode::INVALID_STATE, "Chain exhausted");
    }
    auto [message_key, next_ck] = *result;
    sending_chain = next_ck;

    // Build header: dh_public(32) || msg_num(4 LE)
    RatchetHeader header;
    header.dh_public = dh_local_public;
    header.message_number = msg_num;
    header.previous_chain_length = previous_counter;
    bytes header_bytes = header.to_bytes();

    // Nonce: 8 random + 4 msg_num LE (matching Python/rust wire format)
    std::array<byte, 12> nonce;
    if (RAND_bytes(nonce.data(), 8) != 1) {
        return Result<bytes>(ResultCode::INTERNAL_ERROR, "Failed to generate nonce");
    }
    nonce[8]  = static_cast<byte>(msg_num & 0xFF);
    nonce[9]  = static_cast<byte>((msg_num >> 8) & 0xFF);
    nonce[10] = static_cast<byte>((msg_num >> 16) & 0xFF);
    nonce[11] = static_cast<byte>((msg_num >> 24) & 0xFF);

    // Associated data = caller's AD + header
    bytes full_ad;
    full_ad.reserve(associated_data.size() + header_bytes.size());
    full_ad.insert(full_ad.end(), associated_data.begin(), associated_data.end());
    full_ad.insert(full_ad.end(), header_bytes.begin(), header_bytes.end());

    // Encrypt: nonce(12) || ciphertext || tag(16)
    auto ct_result = Crypto::encrypt(message_key, plaintext, full_ad);
    if (ct_result.is_err()) {
        return ct_result;
    }

    // Wire format: dh_public(32) || msg_num(4) || encrypted_part(nonce+ciphertext+tag)
    bytes wire;
    wire.reserve(32 + 4 + ct_result.value().size());
    wire.insert(wire.end(), dh_local_public.begin(), dh_local_public.end());
    wire.push_back(static_cast<byte>(msg_num & 0xFF));
    wire.push_back(static_cast<byte>((msg_num >> 8) & 0xFF));
    wire.push_back(static_cast<byte>((msg_num >> 16) & 0xFF));
    wire.push_back(static_cast<byte>((msg_num >> 24) & 0xFF));
    wire.insert(wire.end(), ct_result.value().begin(), ct_result.value().end());

    messages_sent++;
    return wire;
}

// ── Decrypt ──────────────────────────────────────────────────────────────────

Result<bytes> DoubleRatchet::ratchet_decrypt(
    const bytes& ciphertext,
    const bytes& associated_data
) {
    // Wire format: dh_public(32) || msg_num(4) || encrypted_part
    if (ciphertext.size() < 32 + 4 + NONCE_LENGTH + TAG_LENGTH) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Ciphertext too short");
    }

    // Parse header
    key remote_dh_pub;
    std::copy(ciphertext.begin(), ciphertext.begin() + 32, remote_dh_pub.begin());

    uint32_t msg_num = static_cast<uint32_t>(ciphertext[32])
                     | (static_cast<uint32_t>(ciphertext[33]) << 8)
                     | (static_cast<uint32_t>(ciphertext[34]) << 16)
                     | (static_cast<uint32_t>(ciphertext[35]) << 24);

    bytes encrypted_part(ciphertext.begin() + 36, ciphertext.end());

    // Try skipped key first
    auto mk = try_skipped_key(remote_dh_pub, msg_num);

    if (!mk.has_value()) {
        // Check if this is from a new remote key (DH ratchet step needed)
        if (remote_dh_pub != dh_remote_public) {
            // Discard old receiving chain and skipped keys (forward secrecy)
            receiving_chain = std::nullopt;
            clear_skipped_keys();

            // Set new remote key and perform DH ratchet
            dh_remote_public = remote_dh_pub;
            dh_ratchet_step();
        }

        // Skip ahead to the needed message number
        if (receiving_chain.has_value()) {
            auto skip_result = skip_message_keys(msg_num);
            if (skip_result.is_err()) {
                return Result<bytes>(skip_result.code(), skip_result.message());
            }

            auto result = receiving_chain->next_message_key();
            if (!result.has_value()) {
                return Result<bytes>(ResultCode::INVALID_STATE, "Receiving chain exhausted");
            }
            auto [next_mk, next_ck] = *result;
            mk = next_mk;
            receiving_chain = next_ck;
        } else {
            return Result<bytes>(ResultCode::INVALID_STATE, "No receiving chain");
        }
    }

    // Build header for AD verification
    RatchetHeader header;
    header.dh_public = remote_dh_pub;
    header.message_number = msg_num;
    header.previous_chain_length = 0; // Not used in AD
    bytes header_bytes = header.to_bytes();

    bytes full_ad;
    full_ad.reserve(associated_data.size() + header_bytes.size());
    full_ad.insert(full_ad.end(), associated_data.begin(), associated_data.end());
    full_ad.insert(full_ad.end(), header_bytes.begin(), header_bytes.end());

    // Decrypt
    auto pt_result = Crypto::decrypt(mk.value(), encrypted_part, full_ad);
    if (pt_result.is_err()) {
        return pt_result;
    }

    messages_received++;
    return pt_result;
}

} // namespace sibna
