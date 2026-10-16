"""
Sibna Protocol v3.0.1 — Cryptographic primitives (pure Python).

Implements the primitives required by the Sibna Protocol using maintained,
audited libraries only:

- Ed25519 signatures (signing/verification) — `cryptography`
- X25519 Diffie-Hellman — `cryptography`
- HKDF-SHA256 (extract + expand) — `hmac`/`hashlib`
- HMAC-SHA256 — `hmac`/`hashlib`
- SHA-256 / SHA-512 — `hashlib`
- BLAKE3 (MANDATORY for X3DH transcript hashing) — `blake3`
- ChaCha20-Poly1305 AEAD — `cryptography`
- CSPRNG — `os.urandom` / `secrets`

No cryptographic primitive is implemented by hand. BLAKE3 is a mandatory
dependency: if it cannot be imported, any operation that requires it raises
Immediately rather than silently substituting SHA-256.

Constants and domain-separation strings match the Rust core exactly
(`core/src/crypto/`, `core/src/handshake/x3dh.rs`) and
`PROTOCOL_SPECIFICATION.md`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Any, Optional, cast

from cryptography.exceptions import InvalidSignature
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

from . import constants as C
from .errors import CryptoError, ValidationError

# ── BLAKE3 (mandatory) ───────────────────────────────────────────────────────
#
# The X3DH transcript hash uses BLAKE3 (PROTOCOL_SPECIFICATION.md §2.3).
# Previously this module fell back to SHA-256 when `blake3` was absent, which
# silently produced a *different* algorithm and broke interoperability with the
# Rust core. BLAKE3 is now a mandatory dependency.
#
# Import at module load time so the failure is loud and immediate, before any
# cryptographic operation runs.

try:
    import blake3 as _blake3_module
except ImportError as _exc:  # pragma: no cover - environment-dependent
    raise ImportError(
        "sibna requires the 'blake3' package for X3DH transcript hashing. "
        "Install it: pip install blake3>=1.0"
    ) from _exc


def blake3_hash(*parts: bytes) -> bytes:
    """BLAKE3-256 digest over the concatenation of `parts`."""
    h = _blake3_module.blake3()
    for p in parts:
        h.update(p)
    return h.digest()


# ── SHA-256 / SHA-512 ───────────────────────────────────────────────────────


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


# ── HKDF-SHA256 ─────────────────────────────────────────────────────────────


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with SHA-256 (RFC 5869)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = C.KEY_LENGTH) -> bytes:
    """HKDF-Expand with SHA-256 (RFC 5869)."""
    if length <= 0 or length > 255 * 32:
        raise ValidationError(f"HKDF output length must be 1..{255 * 32}, got {length}")
    if len(info) > 256:
        raise ValidationError(f"HKDF info must be <= 256 bytes, got {len(info)}")
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
    length: int = C.KEY_LENGTH,
) -> bytes:
    """Full HKDF-SHA256: Extract-then-Expand."""
    prk = hkdf_extract(salt or bytes(C.KEY_LENGTH), ikm)
    return hkdf_expand(prk, info, length)


# ── HMAC-SHA256 ─────────────────────────────────────────────────────────────


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


# ── Secure randomness ───────────────────────────────────────────────────────


def random_bytes(length: int) -> bytes:
    """Cryptographically secure random bytes."""
    if length < 0:
        raise ValidationError("length must be non-negative")
    return os.urandom(length)


# ── Ed25519 ─────────────────────────────────────────────────────────────────


class Ed25519KeyPair:
    """Ed25519 keypair for signing and identity verification.

    Private key material is never included in ``__repr__``.
    """

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None):
        if private_key is None:
            self._private = Ed25519PrivateKey.generate()
        else:
            self._private = private_key
        self._public = self._private.public_key()

    @classmethod
    def from_seed(cls, seed: bytes) -> "Ed25519KeyPair":
        """Create from a 32-byte Ed25519 seed."""
        if len(seed) != C.KEY_LENGTH:
            raise ValidationError(f"Ed25519 seed must be {C.KEY_LENGTH} bytes, got {len(seed)}")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_key(self) -> bytes:
        return self._public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def private_key(self) -> bytes:
        """32-byte raw Ed25519 private seed (treat as secret)."""
        return self._private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @property
    def seed(self) -> bytes:
        return self.private_key

    def sign(self, data: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature over ``data``."""
        return self._private.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Constant-time-ish verification; returns False on invalid signature."""
        try:
            self._public.verify(signature, data)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    @classmethod
    def verify_with_key(cls, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify ``signature`` over ``data`` using raw public key bytes."""
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False
        except Exception:
            return False

    def __repr__(self) -> str:  # pragma: no cover - debugging only
        return f"<Ed25519KeyPair public_key={self.public_key.hex()[:16]}...>"


# ── X25519 ──────────────────────────────────────────────────────────────────


# The 8 known low-order X25519 public keys (small-subgroup attack points).
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
    """X25519 keypair for Diffie-Hellman key agreement.

    Rejects the 8 known low-order public keys to defend against small-subgroup
    attacks, matching `core/src/crypto/mod.rs::validate_public_key`.
    """

    def __init__(self, private_key: Optional[X25519PrivateKey] = None):
        if private_key is None:
            self._private = X25519PrivateKey.generate()
        else:
            self._private = private_key
        self._public = self._private.public_key()

    @classmethod
    def from_seed(cls, seed: bytes) -> "X25519KeyPair":
        """Create from a 32-byte X25519 seed (clamped scalar)."""
        if len(seed) != C.KEY_LENGTH:
            raise ValidationError(f"X25519 seed must be {C.KEY_LENGTH} bytes, got {len(seed)}")
        return cls(X25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_private_bytes(cls, private_bytes: bytes) -> "X25519KeyPair":
        return cls(X25519PrivateKey.from_private_bytes(private_bytes))

    @property
    def public_key(self) -> bytes:
        return self._public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def private_key_bytes(self) -> bytes:
        """32-byte raw X25519 private scalar (treat as secret)."""
        return self._private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @property
    def seed(self) -> bytes:
        return self.private_key_bytes

    def dh(self, remote_public: bytes) -> bytes:
        """X25519 DH -> 32-byte shared secret. Rejects low-order points."""
        if len(remote_public) != C.X25519_PUBLIC_KEY_LENGTH:
            raise ValidationError(
                f"Remote public key must be {C.X25519_PUBLIC_KEY_LENGTH} bytes, "
                f"got {len(remote_public)}"
            )
        if remote_public in LOW_ORDER_POINTS:
            raise CryptoError("Rejecting low-order X25519 public key")
        remote = X25519PublicKey.from_public_bytes(remote_public)
        return self._private.exchange(remote)

    @classmethod
    def generate(cls) -> "X25519KeyPair":
        return cls(X25519PrivateKey.generate())

    def __repr__(self) -> str:  # pragma: no cover - debugging only
        return f"<X25519KeyPair public_key={self.public_key.hex()[:16]}...>"


# ── Identity key derivation ─────────────────────────────────────────────────


def derive_identity_keys(master_seed: bytes) -> tuple[Ed25519KeyPair, X25519KeyPair]:
    """Derive Ed25519 + X25519 identity keypair from a master seed.

    Matches the Rust core (`keystore/IdentityKeyPair::from_bytes`): separate
    HKDF domain separation for each algorithm so knowing one key does not
    reveal the other.

        ed_seed   = HKDF(seed, salt=None, info="SibnaIdentityKey_Ed25519_v1")
        x_seed    = HKDF(seed, salt=None, info="SibnaIdentityKey_X25519_v1")

    Returns ``(ed25519_kp: Ed25519KeyPair, x25519_kp: X25519KeyPair)``.
    """
    if len(master_seed) != C.KEY_LENGTH:
        raise ValidationError(f"master_seed must be {C.KEY_LENGTH} bytes, got {len(master_seed)}")
    ed_seed = hkdf(master_seed, info=b"SibnaIdentityKey_Ed25519_v1", length=C.KEY_LENGTH)
    x_seed = hkdf(master_seed, info=b"SibnaIdentityKey_X25519_v1", length=C.KEY_LENGTH)
    return Ed25519KeyPair.from_seed(ed_seed), X25519KeyPair.from_seed(x_seed)


# ── ChaCha20-Poly1305 ───────────────────────────────────────────────────────


def chacha20_poly1305_encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
    nonce: Optional[bytes] = None,
) -> bytes:
    """Encrypt with ChaCha20-Poly1305.

    Returns ``nonce (12) || ciphertext || tag (16)``.
    """
    if len(key) != C.KEY_LENGTH:
        raise ValidationError(f"Key must be {C.KEY_LENGTH} bytes, got {len(key)}")
    if nonce is None:
        nonce = random_bytes(C.NONCE_LENGTH)
    elif len(nonce) != C.NONCE_LENGTH:
        raise ValidationError(f"Nonce must be {C.NONCE_LENGTH} bytes, got {len(nonce)}")
    cipher = ChaCha20Poly1305(key)
    ct = cipher.encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def chacha20_poly1305_decrypt(
    key: bytes,
    data: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt ``nonce (12) || ciphertext || tag (16)`` produced by encrypt."""
    if len(key) != C.KEY_LENGTH:
        raise ValidationError(f"Key must be {C.KEY_LENGTH} bytes, got {len(key)}")
    if len(data) < C.NONCE_LENGTH + C.TAG_LENGTH:
        raise ValidationError("Ciphertext too short")
    nonce = data[: C.NONCE_LENGTH]
    ct = data[C.NONCE_LENGTH :]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ct, associated_data)


# ── ML-KEM-768 hybrid post-quantum KEM ──────────────────────────────────────


def _ml_kem_768_module() -> tuple[Any, str]:
    """Import the ML-KEM-768 KEM, abstracting over pqcrypto API versions.

    pqcrypto >= 1.0.0:  keygen(), encaps(pk), decaps(sk, ct)
    pqcrypto  0.3.x:    generate_keypair(), encrypt(pk), decrypt(sk, ct)
    All return raw bytes. Sizes are FIPS 203 (pk 1184 / sk 2400 / ct 1088 / ss 32).
    """
    from pqcrypto.kem import ml_kem_768  # type: ignore[import-untyped]

    if hasattr(ml_kem_768, "keygen"):
        return ml_kem_768, "v1"
    return ml_kem_768, "legacy"


def ml_kem_768_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 keypair.

    Returns ``(public_key: bytes[1184], secret_key: bytes[2400])``.
    """
    mod, _ver = _ml_kem_768_module()
    if hasattr(mod, "keygen"):
        return cast(tuple[bytes, bytes], mod.keygen())
    return cast(tuple[bytes, bytes], mod.generate_keypair())


def ml_kem_768_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """ML-KEM-768 encapsulate.

    Returns ``(ciphertext: bytes[1088], shared_secret: bytes[32])``.
    """
    if len(public_key) != C.ML_KEM_768_PUBLIC_KEY_LENGTH:
        raise ValidationError(
            f"ML-KEM-768 public key must be {C.ML_KEM_768_PUBLIC_KEY_LENGTH} bytes, "
            f"got {len(public_key)}"
        )
    mod, _ver = _ml_kem_768_module()
    if hasattr(mod, "encaps"):
        return cast(tuple[bytes, bytes], mod.encaps(public_key))
    return cast(tuple[bytes, bytes], mod.encrypt(public_key))


def ml_kem_768_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """ML-KEM-768 decapsulate -> shared_secret (bytes[32])."""
    if len(secret_key) != C.ML_KEM_768_SECRET_KEY_LENGTH:
        raise ValidationError(
            f"ML-KEM-768 secret key must be {C.ML_KEM_768_SECRET_KEY_LENGTH} bytes, "
            f"got {len(secret_key)}"
        )
    if len(ciphertext) != C.ML_KEM_768_CIPHERTEXT_LENGTH:
        raise ValidationError(
            f"ML-KEM-768 ciphertext must be {C.ML_KEM_768_CIPHERTEXT_LENGTH} bytes, "
            f"got {len(ciphertext)}"
        )
    mod, _ver = _ml_kem_768_module()
    if hasattr(mod, "decaps"):
        return cast(bytes, mod.decaps(secret_key, ciphertext))
    return cast(bytes, mod.decrypt(secret_key, ciphertext))


__all__ = [
    "blake3_hash",
    "sha256",
    "sha512",
    "hkdf",
    "hkdf_extract",
    "hkdf_expand",
    "hmac_sha256",
    "random_bytes",
    "Ed25519KeyPair",
    "X25519KeyPair",
    "LOW_ORDER_POINTS",
    "derive_identity_keys",
    "chacha20_poly1305_encrypt",
    "chacha20_poly1305_decrypt",
    "ml_kem_768_keypair",
    "ml_kem_768_encapsulate",
    "ml_kem_768_decapsulate",
    "C",
]
