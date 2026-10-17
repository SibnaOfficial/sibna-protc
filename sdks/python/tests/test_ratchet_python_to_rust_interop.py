"""Cross-implementation Double Ratchet test: Python encrypts → Rust decrypts.

This test encrypts messages with the Python Double Ratchet and writes
ciphertexts to a JSON file. The Rust test (core/tests/test_python_interop.rs)
reads that file, decrypts with the Rust Double Ratchet, and writes Rust-encrypted
ciphertexts back. A companion Python test then decrypts those Rust ciphertexts.

Execution order (via run_python_rust_interop.sh or manually):
  1. python -m pytest tests/test_ratchet_python_to_rust_interop.py -k python_encrypt
     (writes /tmp/sibna_py_ratchet_ct.json)
  2. cargo test --test test_python_interop   (reads py_ratchet_ct.json,
     writes /tmp/sibna_rust_ratchet_ct.json)
  3. python -m pytest tests/test_ratchet_python_to_rust_interop.py -k python_decrypt
     (reads rust_ratchet_ct.json, decrypts)
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from sibna import (
    DoubleRatchet,
    PreKeyBundle,
    X25519KeyPair,
    Ed25519KeyPair,
)
from sibna.x3dh import x3dh_initiator

# Fixed X25519 secrets matching the Rust interop vectors
ALICE_ID_SK = bytes([0x61] * 32)
BOB_ID_SK = bytes([0x62] * 32)
BOB_SPK_SK = bytes([0x63] * 32)
BOB_OPK_SK = bytes([0x64] * 32)
ALICE_EPH_SK = bytes([0x65] * 32)

PY_CT_PATH = os.path.join(tempfile.gettempdir(), "sibna_py_ratchet_ct.json")
RUST_CT_PATH = os.path.join(tempfile.gettempdir(), "sibna_rust_ratchet_ct.json")


def _make_bundle(identity_ed, identity_x, spk, opk=None):
    return PreKeyBundle(
        identity_key=identity_ed.public_key,
        x25519_identity_key=identity_x.public_key,
        signed_prekey=spk.public_key,
        signed_prekey_signature=identity_ed.sign(b"SibnaSignedPreKey_v3" + spk.public_key),
        onetime_prekey=opk.public_key if opk else None,
        device_id=bytes(16),
    )


@pytest.mark.interop
def test_python_encrypt_writes_ciphertexts_for_rust():
    """Alice (Python) encrypts messages; ciphertexts written for Rust to decrypt."""
    alice_x = X25519KeyPair.from_seed(ALICE_ID_SK)
    alice_eph = X25519KeyPair.from_seed(ALICE_EPH_SK)
    bob_x = X25519KeyPair.from_seed(BOB_ID_SK)
    bob_spk = X25519KeyPair.from_seed(BOB_SPK_SK)
    bob_opk = X25519KeyPair.from_seed(BOB_OPK_SK)
    bob_ed = Ed25519KeyPair()

    bundle = PreKeyBundle(
        identity_key=bob_ed.public_key,
        x25519_identity_key=bob_x.public_key,
        signed_prekey=bob_spk.public_key,
        signed_prekey_signature=bob_ed.sign(b"SibnaSignedPreKey_v3" + bob_spk.public_key),
        onetime_prekey=bob_opk.public_key,
        device_id=bytes(16),
    )

    result = x3dh_initiator(alice_x, alice_eph, bundle)

    alice = DoubleRatchet.from_shared_secret(
        shared_secret=result.shared_secret,
        local_dh_private=alice_eph.private_key_bytes,
        remote_dh_public=bob_spk.public_key,
        role_is_initiator=True,
    )

    messages = [b"Hello Bob #0", b"Hello Bob #1", b"Hello Bob #2"]
    ciphertexts = [alice.ratchet_encrypt(m, b"ad").hex() for m in messages]

    # Verify Python can decrypt its own ciphertexts (sanity check)
    bob = DoubleRatchet.from_shared_secret(
        shared_secret=result.shared_secret,
        local_dh_private=bob_spk.private_key_bytes,
        remote_dh_public=alice_eph.public_key,
        role_is_initiator=False,
    )
    for ct_hex, expected in zip(ciphertexts, messages):
        decrypted = bob.ratchet_decrypt(bytes.fromhex(ct_hex), b"ad")
        assert decrypted == expected

    # Write ciphertexts for Rust to decrypt
    with open(PY_CT_PATH, "w") as f:
        json.dump(
            {
                "ciphertexts": ciphertexts,
                "expected_plaintexts": [m.decode() for m in messages],
                "associated_data": "ad",
                "shared_secret": result.shared_secret.hex(),
                "alice_ephemeral_public": alice_eph.public_key.hex(),
                "bob_signed_prekey_public": bob_spk.public_key.hex(),
            },
            f,
            indent=2,
        )


def test_ratchet_roundtrip_with_fixture_keys(interop_fixture):
    """Python Double Ratchet round-trip using fixture keys.

    The committed fixture (interop_vectors.json) provides fixed test keys and
    the X3DH shared secret for structural validation. These assertions are
    timestamp-independent and never go stale.

    Encryption/decryption uses ciphertexts generated at runtime so the test
    does not depend on pre-committed ciphertexts whose embedded timestamps
    expire after 24 hours (MAX_MESSAGE_AGE_SECS).

    This is a Python round-trip test, not a Rust interop test. Genuine
    Rust<->Python interop is covered by test_python_encrypt_writes_ciphertexts_for_rust
    and test_python_decrypts_rust_generated_ciphertexts.
    """
    # Structural assertions against the committed fixture (timestamp-independent)
    bob_spk = X25519KeyPair.from_seed(BOB_SPK_SK)
    bob_opk = X25519KeyPair.from_seed(BOB_OPK_SK)
    alice_eph = X25519KeyPair.from_seed(ALICE_EPH_SK)
    alice_id_pub = bytes.fromhex(interop_fixture["alice_identity_x25519"])

    assert bob_spk.public_key.hex() == interop_fixture["bob_spk"]
    assert bob_opk.public_key.hex() == interop_fixture["bob_opk"]
    assert alice_eph.public_key.hex() == interop_fixture["alice_ephemeral"]

    shared_secret = bytes.fromhex(interop_fixture["x3dh_shared_secret"])
    assert len(shared_secret) == 32

    # Build matching sessions using the fixture's shared secret
    alice_eph = X25519KeyPair.from_seed(ALICE_EPH_SK)

    alice = DoubleRatchet.from_shared_secret(
        shared_secret=shared_secret,
        local_dh_private=alice_eph.private_key_bytes,
        remote_dh_public=bob_spk.public_key,
        role_is_initiator=True,
    )
    bob = DoubleRatchet.from_shared_secret(
        shared_secret=shared_secret,
        local_dh_private=bob_spk.private_key_bytes,
        remote_dh_public=alice_eph.public_key,
        role_is_initiator=False,
    )

    # Generate fresh ciphertexts at runtime so the test never expires
    messages = [b"Hello Bob #0", b"Hello Bob #1", b"Hello Bob #2"]
    for m in messages:
        ct = alice.ratchet_encrypt(m, b"ad")
        decrypted = bob.ratchet_decrypt(ct, associated_data=b"ad")
        assert decrypted == m


@pytest.mark.interop
def test_python_decrypts_rust_generated_ciphertexts():
    """Python decrypts ciphertexts written by the Rust interop test.

    Depends on rust_ratchet_ct.json being written by the Rust test
    (core/tests/test_python_interop.rs → test_rust_encrypts_writes_ciphertexts_for_python).
    """
    assert os.path.exists(RUST_CT_PATH), (
        f"Rust ciphertext fixture missing at {RUST_CT_PATH}. "
        "Run the Rust test test_python_interop::test_rust_encrypts_writes_ciphertexts_for_python first."
    )

    with open(RUST_CT_PATH, "r") as f:
        data = json.load(f)

    alice_x = X25519KeyPair.from_seed(ALICE_ID_SK)
    alice_eph = X25519KeyPair.from_seed(ALICE_EPH_SK)

    # In Direction B: Rust is Alice (Initiator), Python is Bob (Responder).
    # So Python should create a Bob session.
    bob = DoubleRatchet.from_shared_secret(
        shared_secret=bytes.fromhex(data["shared_secret"]),
        local_dh_private=X25519KeyPair.from_seed(BOB_SPK_SK).private_key_bytes,
        remote_dh_public=bytes.fromhex(data["alice_ephemeral_public"]),
        role_is_initiator=False,
    )

    expected = [b"Hi Alice #0", b"Hi Alice #1", b"Hi Alice #2"]
    for ct_hex, pt in zip(data["ciphertexts"], expected):
        decrypted = bob.ratchet_decrypt(bytes.fromhex(ct_hex), b"ad")
        assert decrypted == pt, f"Failed for {ct_hex[:32]}..."
