"""
Sibna Protocol Python SDK — Unit Tests
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sibna.client import (
    Identity, SibnaClient, AsyncSibnaClient,
    pad_payload, unpad_payload,
    make_signed_envelope, verify_signed_envelope,
    SibnaError, AuthError, NetworkError, CryptoError,
)


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

        # Verify with public key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        vk = Ed25519PublicKey.from_public_bytes(identity.public_key_bytes)
        vk.verify(sig, data)  # Should not raise

    def test_sign_hex(self):
        identity = Identity()
        sig_hex = identity.sign_hex(b"test")
        assert len(sig_hex) == 128  # 64 bytes * 2 hex chars

    def test_save_load(self, tmp_path):
        identity = Identity()
        path = tmp_path / "identity.bin"
        identity.save(str(path))

        loaded = Identity.load(str(path))
        assert loaded.public_key_bytes == identity.public_key_bytes

    def test_repr(self):
        identity = Identity()
        r = repr(identity)
        assert "Identity" in r
        assert "..." in r


class TestPadding:
    def test_pad_unpad_roundtrip(self):
        data = b"Hello, World!"
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        unpadded = unpad_payload(padded)
        assert unpadded == data

    def test_pad_empty(self):
        padded = pad_payload(b"")
        unpadded = unpad_payload(padded)
        assert unpadded == b""

    def test_pad_large(self):
        data = b"x" * 5000
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        unpadded = unpad_payload(padded)
        assert unpadded == data

    def test_unpad_empty_raises(self):
        with pytest.raises(CryptoError):
            unpad_payload(b"")

    # FIX: Phase 3.2 — SIBNA-2026-018 parity with the Rust core.
    # extra_blocks is drawn uniformly from 0..7, giving 8 possible
    # on-wire sizes for a fixed plaintext. 64 trials on the same
    # plaintext must hit at least 2 distinct sizes; with 8 possible
    # values the probability of all 64 picking the same size is
    # (1/8)^63, effectively zero.
    def test_padding_size_distribution_not_constant(self):
        msg = b"constant-size message"
        sizes = set()
        for _ in range(64):
            padded = pad_payload(msg)
            assert len(padded) % 1024 == 0
            sizes.add(len(padded))
        assert len(sizes) >= 2, (
            f"SIBNA-2026-018 regression: padded size is constant across "
            f"64 trials, only saw {sizes}"
        )

    # FIX: Phase 3.2 — prefix_len must be in [1, 8] on every call.
    def test_prefix_len_in_range(self):
        for _ in range(32):
            padded = pad_payload(b"ping")
            assert 1 <= padded[0] <= 8

    # FIX: Phase 3.2 — hand-built Rust-shaped buffer must unpad correctly.
    # Layout: [ prefix_len(1) | prefix_noise(3) | plaintext(5) | padding |
    #           pad_len(2, LE) ]
    # Total must be 1024 (one block). For prefix_len=3 and
    # plaintext="hello" (5 bytes), min_total = 1+3+5+2 = 11, so
    # min_pad_len = 1024 - 11 = 1013.
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
        envelope = make_signed_envelope(
            identity,
            recipient_id="aabbccdd",
            payload_hex="deadbeef",
        )
        assert verify_signed_envelope(envelope)

    def test_verify_tampered(self):
        identity = Identity()
        envelope = make_signed_envelope(
            identity,
            recipient_id="aabbccdd",
            payload_hex="deadbeef",
        )
        # Tamper with payload
        envelope["payload_hex"] = "deadbeef01"
        assert not verify_signed_envelope(envelope)

    def test_verify_wrong_sender(self):
        identity1 = Identity()
        identity2 = Identity()
        envelope = make_signed_envelope(
            identity1,
            recipient_id="aabbccdd",
            payload_hex="deadbeef",
        )
        # Change sender to identity2
        envelope["sender_id"] = identity2.public_key_hex
        assert not verify_signed_envelope(envelope)

    def test_envelope_fields(self):
        identity = Identity()
        envelope = make_signed_envelope(
            identity,
            recipient_id="aabbccdd",
            payload_hex="deadbeef",
            compress=True,
        )
        assert envelope["recipient_id"] == "aabbccdd"
        assert envelope["payload_hex"] == "deadbeef"
        assert envelope["sender_id"] == identity.public_key_hex
        assert envelope["compressed"] is True
        assert "timestamp" in envelope
        assert "message_id" in envelope
        assert "signature_hex" in envelope


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
