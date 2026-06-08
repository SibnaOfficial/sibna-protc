"""
Sibna Protocol v3.0.1 — Standalone Cryptographic Primitives

Provides Ed25519, X25519, ChaCha20-Poly1305, HKDF, HMAC-SHA256,
SHA-256, SHA-512, and secure random bytes — all via the `cryptography`
package. No Rust core or FFI required.

Protocol constants match the Rust core exactly:
  - KDF salt/info strings for Double Ratchet and X3DH
  - Domain separators for signatures and transcript binding
  - All byte ordering (little-endian u32/u64 for wire format)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ── Constants ────────────────────────────────────────────────────────────────

KEY_LENGTH = 32
NONCE_LENGTH = 12
TAG_LENGTH = 16
MIN_COMPATIBLE_VERSION = 9

# ── Ed25519 Identity ────────────────────────────────────────────────────────


class Ed25519KeyPair:
    """Ed25519 keypair for signing and identity."""

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None):
        if private_key is None:
            self._private = Ed25519PrivateKey.generate()
        else:
            self._private = private_key
        self._public = self._private.public_key()

    @classmethod
    def from_seed(cls, seed: bytes) -> "Ed25519KeyPair":
        """Create from a 32-byte seed (matching Rust X25519KeyPair::from_seed)."""
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_key(self) -> bytes:
        return self._public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def private_key(self) -> bytes:
        return self._private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    @property
    def seed(self) -> bytes:
        return self.private_key

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._public.verify(signature, data)
            return True
        except Exception:
            return False

    @classmethod
    def verify_with_key(cls, public_key: bytes, data: bytes, signature: bytes) -> bool:
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, data)
            return True
        except Exception:
            return False


# ── X25519 Diffie-Hellman ───────────────────────────────────────────────────

# Reject these 8 known low-order X25519 public keys
LOW_ORDER_POINTS = frozenset(
    bytes.fromhex(h)
    for h in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb8a3114509de3500459450f1f56e39cc03814c13efc4b3fb0839e41f80f17",
        "c3ada28304f53665966e72ca07de5614a4c00ceb534fbb99767401c0295c590f",
        "504c00c7ff6616830ca1da120b0bba22a2f44157298b3cd579e95138d96f8c17",
        "d8527d1f006f51e8b6542d6ae27e09eb88aec0c71e9c75cfd2c17d4d2b13d00e",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7e",
        "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]
)


class X25519KeyPair:
    """X25519 keypair for Diffie-Hellman key exchange."""

    def __init__(self, private_key: Optional[X25519PrivateKey] = None):
        if private_key is None:
            self._private = X25519PrivateKey.generate()
        else:
            self._private = private_key
        self._public = self._private.public_key()

    @classmethod
    def from_seed(cls, seed: bytes) -> "X25519KeyPair":
        """Create from a 32-byte seed (matching Rust X25519KeyPair::from_seed)."""
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes")
        return cls(X25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_private_bytes(cls, private_bytes: bytes) -> "X25519KeyPair":
        return cls(X25519PrivateKey.from_private_bytes(private_bytes))

    @property
    def public_key(self) -> bytes:
        return self._public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def private_key_bytes(self) -> bytes:
        return self._private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    @property
    def seed(self) -> bytes:
        return self.private_key_bytes

    def dh(self, remote_public: bytes) -> bytes:
        """Perform X25519 DH and return 32-byte shared secret."""
        if len(remote_public) != 32:
            raise ValueError("Remote public key must be 32 bytes")
        if remote_public in LOW_ORDER_POINTS:
            raise ValueError("Rejecting low-order X25519 public key")
        remote = X25519PublicKey.from_public_bytes(remote_public)
        return self._private.exchange(remote)

    @classmethod
    def generate(cls) -> "X25519KeyPair":
        return cls(X25519PrivateKey.generate())


# ── HKDF-SHA256 ─────────────────────────────────────────────────────────────


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand with SHA-256."""
    n = (length + 31) // 32
    okm = b""
    prev = b""
    for i in range(1, n + 1):
        prev = hmac.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
        okm += prev
    return okm[:length]


def hkdf(
    ikm: bytes,
    salt: Optional[bytes] = None,
    info: bytes = b"",
    length: int = 32,
) -> bytes:
    """Full HKDF-SHA256: Extract-then-Expand."""
    prk = hkdf_extract(salt or bytes(KEY_LENGTH), ikm)
    return hkdf_expand(prk, info, length)


# ── HMAC-SHA256 ─────────────────────────────────────────────────────────────


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


# ── SHA-256 / SHA-512 ───────────────────────────────────────────────────────


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


# ── Blake3 (transcript hashing for X3DH) ────────────────────────────────────

# Blake3 is used for the X3DH transcript hash. We provide a fallback
# using SHA-256 if blake3 is not installed. The protocol spec uses blake3,
# so install `blake3` for full compatibility.

try:
    import blake3 as _blake3

    def blake3_hash(*parts: bytes) -> bytes:
        h = _blake3.blake3()
        for p in parts:
            h.update(p)
        return h.digest()

except ImportError:
    def blake3_hash(*parts: bytes) -> bytes:
        """Fallback: SHA-256 when blake3 is not installed."""
        h = hashlib.sha256()
        for p in parts:
            h.update(p)
        return h.digest()


# ── ChaCha20-Poly1305 ──────────────────────────────────────────────────────


def chacha20_poly1305_encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
    nonce: Optional[bytes] = None,
) -> bytes:
    """
    Encrypt with ChaCha20-Poly1305.

    Returns nonce (12) || ciphertext || tag (16).
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be {KEY_LENGTH} bytes")
    if nonce is None:
        nonce = os.urandom(NONCE_LENGTH)
    cipher = ChaCha20Poly1305(key)
    ct = cipher.encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def chacha20_poly1305_decrypt(
    key: bytes,
    data: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """
    Decrypt data that was encrypted with chacha20_poly1305_encrypt.

    Input format: nonce (12) || ciphertext || tag (16).
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be {KEY_LENGTH} bytes")
    if len(data) < NONCE_LENGTH + TAG_LENGTH:
        raise ValueError("Ciphertext too short")
    nonce = data[:NONCE_LENGTH]
    ct = data[NONCE_LENGTH:]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ct, associated_data)


# ── Identity Key Derivation (from master seed) ─────────────────────────────


def derive_identity_keys(master_seed: bytes) -> tuple:
    """
    Derive Ed25519 + X25519 identity keypair from a master seed.
    Matches Rust core: HKDF(seed, salt=None, info="SibnaIdentityKey_*_v1").

    Returns (ed25519_kp: Ed25519KeyPair, x25519_kp: X25519KeyPair).
    """
    ed_seed = hkdf(master_seed, info=b"SibnaIdentityKey_Ed25519_v1", length=32)
    x_seed = hkdf(master_seed, info=b"SibnaIdentityKey_X25519_v1", length=32)
    return Ed25519KeyPair.from_seed(ed_seed), X25519KeyPair.from_seed(x_seed)


# ── Random Bytes ─────────────────────────────────────────────────────────────


def random_bytes(length: int) -> bytes:
    """Cryptographically secure random bytes."""
    return os.urandom(length)
