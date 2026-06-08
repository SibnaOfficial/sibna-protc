#pragma once

#include "types.hpp"
#include "error.hpp"
#include "utils.hpp"
#include "crypto.hpp"
#include <unordered_map>
#include <map>

namespace sibna {

// ── Constants ────────────────────────────────────────────────────────────────

constexpr size_t MAX_CHAIN_MESSAGES = 4000;
constexpr size_t MAX_SKIPPED_MESSAGES = 2000;
constexpr uint64_t MAX_MESSAGE_KEY_AGE_SECS = 86400;

// Chain key derivation seeds
static constexpr byte MESSAGE_KEY_SEED = 0x01;
static constexpr byte CHAIN_KEY_SEED = 0x02;
static constexpr byte HEADER_KEY_SEED = 0x03;

// ── ChainKey ─────────────────────────────────────────────────────────────────

struct ChainKey {
    key chain_key;
    uint64_t index = 0;
    uint64_t created_at = 0;
    uint64_t max_messages = MAX_CHAIN_MESSAGES;

    ChainKey();
    explicit ChainKey(const key& k);
    ChainKey(const key& k, uint64_t idx);

    // Derive next message key and advance chain.
    // Returns (message_key, next_chain_key) or nullopt if chain exhausted.
    std::optional<std::pair<key, ChainKey>> next_message_key();

    // Derive header key from current chain key
    key derive_header_key() const;

    uint64_t remaining_messages() const;
    bool needs_rotation() const;
};

// ── RatchetHeader ────────────────────────────────────────────────────────────

struct RatchetHeader {
    key dh_public;           // 32 bytes
    uint32_t message_number; // 4 bytes LE
    uint32_t previous_chain_length; // 4 bytes LE

    static constexpr size_t HEADER_SIZE = 32 + 4 + 4; // 40 bytes

    bytes to_bytes() const;
    static Result<RatchetHeader> from_bytes(const bytes& data);
    Result<void> validate() const;
};

// ── DoubleRatchet ────────────────────────────────────────────────────────────

class DoubleRatchet {
public:
    DoubleRatchet();

    // Create initial DoubleRatchet state from X3DH shared secret
    static DoubleRatchet from_shared_secret(
        const key& shared_secret,
        const key& local_dh_private,
        const key& remote_dh_public,
        bool role_is_initiator
    );

    // ── Encrypt ──────────────────────────────────────────────────────────────
    // Wire format: dh_public(32) || msg_num(4) || nonce(12) || encrypted_part
    Result<bytes> ratchet_encrypt(
        const bytes& plaintext,
        const bytes& associated_data = {}
    );

    // ── Decrypt ──────────────────────────────────────────────────────────────
    Result<bytes> ratchet_decrypt(
        const bytes& ciphertext,
        const bytes& associated_data = {}
    );

    // ── State ────────────────────────────────────────────────────────────────
    key root_key;
    std::optional<ChainKey> sending_chain;
    std::optional<ChainKey> receiving_chain;
    key dh_local_private;
    key dh_local_public;
    key dh_remote_public;
    uint32_t previous_counter = 0;
    size_t max_skip = MAX_SKIPPED_MESSAGES;

    // Skipped message keys: (dh_public_bytes, message_number) -> message_key
    std::map<std::pair<bytes, uint32_t>, key> skipped_keys;

    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;

    void clear_skipped_keys();

private:
    // KDF_RK: derive new root_key and chain_key from DH output
    std::pair<key, key> kdf_rk(const key& dh_out);

    // DH ratchet step (receive step + send step)
    void dh_ratchet_step();

    // Perform DH ratchet for sending (when no sending chain exists)
    void perform_send_ratchet();

    // Skip message keys in receiving chain until target
    Result<void> skip_message_keys(uint32_t until);

    // Try skipped key
    std::optional<key> try_skipped_key(const key& dh_public, uint32_t msg_num);
};

} // namespace sibna
