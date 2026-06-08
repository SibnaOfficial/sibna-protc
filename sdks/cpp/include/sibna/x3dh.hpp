#pragma once

#include "types.hpp"
#include "error.hpp"
#include "utils.hpp"
#include <optional>

namespace sibna {

/// X3DH key agreement result
struct X3dhResult {
    key shared_secret;
    std::vector<key> dh_results;
};

/// X3DH key agreement — initiator side
///
/// DH1 = DH(our_identity_x25519, peer_spk)
/// DH2 = DH(our_ephemeral, peer_identity_x25519)
/// DH3 = DH(our_ephemeral, peer_spk)
/// DH4 = DH(our_ephemeral, peer_opk)  [optional]
Result<X3dhResult> x3dh_initiator(
    const key& our_identity_private,
    const key& our_ephemeral_private,
    const key& peer_identity_public,
    const key& peer_signed_prekey,
    const std::optional<key>& peer_onetime_prekey,
    const device_id& our_device_id,
    const device_id& peer_device_id,
    const std::array<byte, 32>& transcript_hash_ext
);

/// X3DH key agreement — responder side
///
/// DH1 = DH(our_spk, peer_identity)
/// DH2 = DH(our_identity, peer_ephemeral)
/// DH3 = DH(our_spk, peer_ephemeral)
/// DH4 = DH(our_opk, peer_ephemeral)  [optional]
Result<X3dhResult> x3dh_responder(
    const key& our_identity_private,
    const key& our_signed_prekey_private,
    const std::optional<key>& our_onetime_prekey_private,
    const key& peer_identity_public,
    const key& peer_ephemeral_public,
    const device_id& our_device_id,
    const device_id& peer_device_id,
    const std::array<byte, 32>& transcript_hash_ext
);

/// Derive session key from X3DH shared secret
///
/// HKDF(shared_secret, salt="SibnaSession_v3",
///       info="SibnaRootAndChainKey_v3", length=64)
/// Returns root_key(32) + chain_key(32)
Result<std::pair<key, key>> x3dh_derive_session_keys(
    const key& shared_secret
);

} // namespace sibna
