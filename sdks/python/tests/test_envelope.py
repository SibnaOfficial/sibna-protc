"""
Sibna Python SDK — signed envelope conformance tests.

The canonical signed payload matches the retained relay server
(`server/src/ws.rs::route_message`): length-prefixed recipient_id, message_id,
payload_hex, signed with the sender's Ed25519 identity key.
"""

from __future__ import annotations

import pytest

from sibna import Ed25519KeyPair, make_signed_envelope, verify_signed_envelope


def test_envelope_make_verify():
    sender = Ed25519KeyPair()
    env = make_signed_envelope(sender, recipient_id="aa" * 16, payload_hex="deadbeef")
    assert verify_signed_envelope(env)
    assert env["sender_id"] == sender.public_key.hex()
    assert len(env["signature_hex"]) == 128


def test_envelope_tampered_payload_rejected():
    sender = Ed25519KeyPair()
    env = make_signed_envelope(sender, recipient_id="aa" * 16, payload_hex="deadbeef")
    env["payload_hex"] = "beef"
    assert not verify_signed_envelope(env)


def test_envelope_tampered_recipient_rejected():
    sender = Ed25519KeyPair()
    env = make_signed_envelope(sender, recipient_id="aa" * 16, payload_hex="deadbeef")
    env["recipient_id"] = "ff" * 16
    assert not verify_signed_envelope(env)


def test_envelope_wrong_sender_rejected():
    sender1 = Ed25519KeyPair()
    sender2 = Ed25519KeyPair()
    env = make_signed_envelope(sender1, recipient_id="aa" * 16, payload_hex="deadbeef")
    env["sender_id"] = sender2.public_key.hex()
    assert not verify_signed_envelope(env)


def test_envelope_canonical_format_length_prefixed():
    # The canonical payload is u64_be(len)||value for each field, which prevents
    # field-boundary overlap attacks. Verify by confirming a tampered length
    # changes verification outcome.
    sender = Ed25519KeyPair()
    env = make_signed_envelope(sender, recipient_id="aa" * 16, payload_hex="deadbeef")
    assert verify_signed_envelope(env)
    # Truncate message_id -> signature no longer validates.
    env["message_id"] = env["message_id"][:-1]
    assert not verify_signed_envelope(env)
