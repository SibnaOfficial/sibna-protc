"""
Sibna Python SDK — Group messaging conformance tests.

Covers sender-key creation, encryption/decryption with signing, signature
verification, message-number advancement, epoch rollback protection, and
group size limits. Wire format matches `sibna.group.GroupMessage.to_bytes`.
"""

from __future__ import annotations

import pytest

from sibna import Ed25519KeyPair, GroupSession, SafetyNumber, SenderKey, SenderKeyMessage
from sibna.crypto import X25519KeyPair
from sibna.errors import CryptoError


def test_group_encrypt_decrypt_roundtrip():
    sender = Ed25519KeyPair()
    group = GroupSession.create()
    # Snapshot the sender key before encrypting (message_number == 0).
    sk0 = SenderKey(
        chain_key=group._sender_key.chain_key,
        key_id=group._sender_key.key_id,
        message_number=0,
    )
    msg = group.encrypt(b"hello group", signing_identity=sender)

    # A receiver holding the same sender-key state can decrypt.
    receiver = GroupSession.create(group.group_id)
    receiver._sender_keys[sender.public_key] = sk0
    assert receiver.decrypt(msg, sender.public_key) == b"hello group"


def test_group_sender_key_chain_advances():
    group = GroupSession.create()
    m1 = group.encrypt(b"one")
    m2 = group.encrypt(b"two")
    assert m1.message_number == 0
    assert m2.message_number == 1


def test_group_unsigned_message_rejected():
    group = GroupSession.create()
    sender = Ed25519KeyPair()
    msg = group.encrypt(b"hello")  # no signing identity -> unsigned
    receiver = GroupSession.create(group.group_id)
    receiver._sender_keys[sender.public_key] = group._sender_key
    with pytest.raises(CryptoError):
        receiver.decrypt(msg, sender.public_key)


def test_group_tampered_signature_rejected():
    group = GroupSession.create()
    sender = Ed25519KeyPair()
    msg = group.encrypt(b"hello", signing_identity=sender)
    msg.sender_signature = bytes(64)  # invalid signature
    receiver = GroupSession.create(group.group_id)
    receiver._sender_keys[sender.public_key] = group._sender_key
    with pytest.raises(CryptoError):
        receiver.decrypt(msg, sender.public_key)


def test_group_epoch_rollback_rejected():
    group = GroupSession.create()
    sender = Ed25519KeyPair()
    msg = group.encrypt(b"hello", signing_identity=sender)
    receiver = GroupSession.create(group.group_id)
    receiver._sender_keys[sender.public_key] = group._sender_key
    receiver.epoch = msg.epoch + 1  # receiver ahead -> stale message
    with pytest.raises(CryptoError):
        receiver.decrypt(msg, sender.public_key)


def test_group_key_distribution_roundtrip():
    group = GroupSession.create()
    sender = Ed25519KeyPair()
    member_x = X25519KeyPair.generate()
    dists = group.get_key_distribution_message(sender, [member_x.public_key])
    assert len(dists) == 1
    dist = dists[0]
    assert dist.verify_signature()

    # Serialize/deserialize the distribution message.
    dist2 = SenderKeyMessage.from_bytes(dist.to_bytes())
    assert dist2.to_bytes() == dist.to_bytes()
    assert dist2.verify_signature()

    # Receiver with the matching ephemeral private key recovers the chain key.
    # Re-derive using the same ephemeral: we need the ephemeral used. Since
    # get_key_distribution_message generates it internally, instead verify the
    # encrypted key decrypts to a 32-byte chain key with a matching ephemeral by
    # round-tripping via process_key_distribution with a constructed ephemeral.
    # Build a fresh distribution manually with a known ephemeral.
    ephemeral = X25519KeyPair.generate()
    shared = ephemeral.dh(member_x.public_key)
    from sibna.crypto import hkdf, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
    from sibna import constants as C

    enc_key = hkdf(shared, salt=None, info=C.GROUP_KEY_DISTRIBUTE_INFO, length=C.KEY_LENGTH)
    encrypted = chacha20_poly1305_encrypt(enc_key, group._sender_key.chain_key)
    dist_manual = SenderKeyMessage(
        group_id=group.group_id,
        sender_public_key=sender.public_key,
        encrypted_key=encrypted,
        signature=b"",
        key_id=group._sender_key.key_id,
    )
    dist_manual.sign(sender)
    receiver = GroupSession.create(group.group_id)
    receiver.process_key_distribution(dist_manual, member_x, ephemeral.public_key)
    assert receiver._sender_keys[sender.public_key].chain_key == group._sender_key.chain_key


def test_group_size_limit():
    group = GroupSession.create()
    for i in range(256):
        group.add_member(bytes([i]) * 32)
    with pytest.raises(Exception):
        group.add_member(bytes([255]) * 32)


def test_safety_number_symmetry_and_digits():
    k1 = bytes.fromhex("aa" * 32)
    k2 = bytes.fromhex("bb" * 32)
    sn1 = SafetyNumber.calculate(k1, k2)
    sn2 = SafetyNumber.calculate(k2, k1)
    assert sn1.verify(sn2)
    assert sn1.as_string() == sn2.as_string()
    digits = "".join(c for c in sn1.as_string() if c.isdigit())
    assert len(digits) == 80


def test_safety_number_different_keys_differ():
    k1 = bytes.fromhex("aa" * 32)
    k2 = bytes.fromhex("bb" * 32)
    k3 = bytes.fromhex("cc" * 32)
    assert not SafetyNumber.calculate(k1, k2).verify(SafetyNumber.calculate(k1, k3))


def test_safety_number_parse_roundtrip():
    k1 = bytes.fromhex("aa" * 32)
    k2 = bytes.fromhex("bb" * 32)
    sn = SafetyNumber.calculate(k1, k2)
    parsed = SafetyNumber.parse(sn.as_string())
    assert sn.verify(parsed)
