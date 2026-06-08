"""
Sibna Protocol — Cross-SDK Interop Test

Generates test vectors with fixed seeds so both Python and JS
derive the same keys independently and verify interoperability.
"""

import json
import sys
import os
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sibna.crypto import X25519KeyPair, Ed25519KeyPair, derive_identity_keys
from sibna.x3dh import PreKeyBundle, x3dh_initiator, x3dh_responder
from sibna.session import Session
from sibna.safety_number import SafetyNumber

ALICE_SEED = hashlib.sha256(b"sibna-test-alice-seed-v1").digest()
BOB_SEED = hashlib.sha256(b"sibna-test-bob-seed-v1").digest()


def generate_test_vectors():
    vectors = {}
    vectors['alice_seed'] = ALICE_SEED.hex()
    vectors['bob_seed'] = BOB_SEED.hex()

    alice_ed, alice_x25519 = derive_identity_keys(ALICE_SEED)
    bob_ed, bob_x25519 = derive_identity_keys(BOB_SEED)

    vectors['alice_identity_ed25519'] = alice_ed.public_key.hex()
    vectors['alice_identity_x25519'] = alice_x25519.public_key.hex()
    vectors['bob_identity_ed25519'] = bob_ed.public_key.hex()
    vectors['bob_identity_x25519'] = bob_x25519.public_key.hex()

    bob_signed_prekey = X25519KeyPair.from_seed(hashlib.sha256(b"sibna-test-bob-sp").digest())
    bob_one_time_prekey = X25519KeyPair.from_seed(hashlib.sha256(b"sibna-test-bob-opk").digest())

    vectors['bob_spk_seed'] = hashlib.sha256(b"sibna-test-bob-sp").digest().hex()
    vectors['bob_opk_seed'] = hashlib.sha256(b"sibna-test-bob-opk").digest().hex()

    bob_bundle = PreKeyBundle(
        identity_key=bob_ed.public_key,
        x25519_identity_key=bob_x25519.public_key,
        signed_prekey=bob_signed_prekey.public_key,
        signed_prekey_signature=bob_ed.sign(bob_signed_prekey.public_key),
        onetime_prekey=bob_one_time_prekey.public_key,
    )

    alice_ephemeral_seed = hashlib.sha256(b"sibna-test-alice-eph").digest()
    alice_ephemeral = X25519KeyPair.from_seed(alice_ephemeral_seed)
    vectors['alice_eph_seed'] = alice_ephemeral_seed.hex()

    x3dh_result = x3dh_initiator(alice_x25519, alice_ephemeral, bob_bundle)
    vectors['x3dh_shared_secret'] = x3dh_result.shared_secret.hex()

    bob_result = x3dh_responder(
        bob_x25519, bob_signed_prekey, bob_one_time_prekey,
        alice_x25519.public_key, alice_ephemeral.public_key,
    )
    assert x3dh_result.shared_secret == bob_result.shared_secret

    alice_session = Session.from_shared_secret(
        x3dh_result.shared_secret,
        alice_ephemeral.private_key_bytes,
        bob_signed_prekey.public_key,
        role_is_initiator=True,
    )
    bob_session = Session.from_shared_secret(
        bob_result.shared_secret,
        bob_signed_prekey.private_key_bytes,
        alice_ephemeral.public_key,
        role_is_initiator=False,
    )

    alice_to_bob = []
    for i in range(5):
        msg = f"Hello Bob #{i}".encode()
        ct = alice_session.encrypt(msg)
        alice_to_bob.append(ct.hex())
    vectors['alice_to_bob'] = alice_to_bob

    bob_decrypted = []
    for ct_hex in alice_to_bob:
        ct = bytes.fromhex(ct_hex)
        pt = bob_session.decrypt(ct)
        bob_decrypted.append(pt.decode())
    vectors['bob_decrypted'] = bob_decrypted

    bob_to_alice = []
    for i in range(3):
        msg = f"Hello Alice #{i}".encode()
        ct = bob_session.encrypt(msg)
        bob_to_alice.append(ct.hex())
    vectors['bob_to_alice'] = bob_to_alice

    alice_decrypted = []
    for ct_hex in bob_to_alice:
        ct = bytes.fromhex(ct_hex)
        pt = alice_session.decrypt(ct)
        alice_decrypted.append(pt.decode())
    vectors['alice_decrypted'] = alice_decrypted

    sn = SafetyNumber.calculate(alice_ed.public_key, bob_ed.public_key)
    vectors['safety_number'] = sn.as_string()
    vectors['safety_number_fingerprint'] = sn.fingerprint.hex()

    return vectors


if __name__ == "__main__":
    vectors = generate_test_vectors()
    print(json.dumps(vectors, indent=2))
    print("\n✓ Test vectors generated successfully!", file=sys.stderr)
