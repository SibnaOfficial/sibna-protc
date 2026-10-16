"""
Sibna Python SDK — legacy client/padding/envelope tests, ported to the new
module layout (`sibna.padding`, `sibna.envelope`, `sibna.client`).
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from sibna.padding import pad_payload, unpad_payload
from sibna.envelope import make_signed_envelope, verify_signed_envelope
from sibna.client import (
    Identity,
    SibnaClient,
    SibnaError,
    AuthError,
    NetworkError,
    CryptoError,
)
from sibna.errors import ValidationError


class TestIdentity:
    def test_generate_identity(self):
        identity = Identity()
        assert len(identity.public_key_bytes) == 32
        assert len(identity.private_key_bytes) == 32
        assert len(identity.public_key_hex) == 64

    def test_sign_verify(self):
        identity = Identity()
        data = b"test message"
        sig = identity.sign(data)
        assert len(sig) == 64

    def test_save_load(self, tmp_path):
        identity = Identity()
        path = tmp_path / "identity.bin"
        identity.save(str(path))
        loaded = Identity.load(str(path))
        assert loaded.public_key_bytes == identity.public_key_bytes


class TestPadding:
    def test_pad_unpad_roundtrip(self):
        data = b"Hello, World!"
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        assert unpad_payload(padded) == data

    def test_pad_empty(self):
        assert unpad_payload(pad_payload(b"")) == b""

    def test_pad_large(self):
        data = b"x" * 5000
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        assert unpad_payload(padded) == data

    def test_unpad_empty_raises(self):
        with pytest.raises(CryptoError):
            unpad_payload(b"")

    def test_padding_size_distribution_not_constant(self):
        msg = b"constant-size message"
        sizes = set()
        for _ in range(64):
            padded = pad_payload(msg)
            assert len(padded) % 1024 == 0
            sizes.add(len(padded))
        assert len(sizes) >= 2

    def test_prefix_len_in_range(self):
        for _ in range(32):
            padded = pad_payload(b"ping")
            assert 1 <= padded[0] <= 8

    def test_unpad_wire_format_matches_rust(self):
        pad_len = 1013
        buf = bytes(
            [0x03, 0xAA, 0xBB, 0xCC]
            + list(b"hello")
            + [0] * pad_len
            + [pad_len & 0xFF, (pad_len >> 8) & 0xFF]
        )
        assert len(buf) == 1024
        assert unpad_payload(buf) == b"hello"


class TestSignedEnvelope:
    def test_make_verify(self):
        identity = Identity()
        envelope = make_signed_envelope(identity, recipient_id="aabbccdd", payload_hex="deadbeef")
        assert verify_signed_envelope(envelope)

    def test_verify_tampered(self):
        identity = Identity()
        envelope = make_signed_envelope(identity, recipient_id="aabbccdd", payload_hex="deadbeef")
        envelope["payload_hex"] = "deadbeef01"
        assert not verify_signed_envelope(envelope)

    def test_verify_wrong_sender(self):
        identity1 = Identity()
        identity2 = Identity()
        envelope = make_signed_envelope(identity1, recipient_id="aabbccdd", payload_hex="deadbeef")
        envelope["sender_id"] = identity2.public_key_hex
        assert not verify_signed_envelope(envelope)


class TestClient:
    def test_generate_identity(self):
        client = SibnaClient(server="http://localhost:8080")
        identity = client.generate_identity()
        assert client.identity is not None
        assert len(identity.public_key_bytes) == 32

    def test_auth_without_identity_raises(self):
        client = SibnaClient(server="http://localhost:8080")
        with pytest.raises(AuthError):
            client.authenticate()

    def test_repr(self):
        client = SibnaClient(server="http://localhost:8080")
        client.generate_identity()
        r = repr(client)
        assert "SibnaClient" in r
        assert "localhost" in r


class TestErrors:
    def test_sibna_error(self):
        err = SibnaError("test error", 400)
        assert str(err) == "test error"
        assert err.status_code == 400

    def test_auth_error(self):
        err = AuthError("auth failed", 401)
        assert err.status_code == 401

    def test_network_error(self):
        err = NetworkError("network failed", 503)
        assert err.status_code == 503

    def test_crypto_error(self):
        err = CryptoError("crypto failed")
        assert str(err) == "crypto failed"

    def test_validation_error(self):
        err = ValidationError("bad input")
        assert str(err) == "bad input"
