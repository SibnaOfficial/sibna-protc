"""
Sibna Protocol Python SDK v3.0.1 — Fully Standalone Edition

Complete cryptographic protocol implementation in pure Python.
No Rust core, FFI, or native library required.

Install:
    pip install cryptography

Optional (for X3DH transcript hash compatibility with Rust core):
    pip install blake3

Example — full end-to-end encrypted session:
    >>> from sibna import Session, PreKeyBundle
    >>> from sibna.crypto import X25519KeyPair, Ed25519KeyPair, derive_identity_keys
    >>>
    >>> # Generate identity
    >>> ed_kp, x_kp = derive_identity_keys(os.urandom(32))
    >>>
    >>> # Create prekey bundle
    >>> bundle = PreKeyBundle(ed_kp.public_key, x_kp.public_key, ed_kp.sign(x_kp.public_key))
    >>>
    >>> # Initiator
    >>> s1 = Session()
    >>> eph = X25519KeyPair.generate()
    >>> s1.initiate_as_initiator(x_kp, eph, bundle)
    >>>
    >>> # Encrypt
    >>> ct = s1.encrypt(b"Hello!")
    >>>
    >>> # Responder
    >>> s2 = Session()
    >>> s2.initiate_as_responder(x_kp, x_kp, None, eph.public_key, eph.public_key)
    >>> pt = s2.decrypt(ct)
"""

__version__ = "3.0.1"
__author__ = "Sibna Security Team"
__license__ = "Apache-2.0 OR MIT"

from .crypto import (
    Ed25519KeyPair,
    X25519KeyPair,
    random_bytes,
    hkdf,
    hmac_sha256,
    sha256,
    sha512,
    chacha20_poly1305_encrypt,
    chacha20_poly1305_decrypt,
    derive_identity_keys,
    KEY_LENGTH,
    NONCE_LENGTH,
)
from .x3dh import (
    PreKeyBundle,
    X3DHResult,
    x3dh_initiator,
    x3dh_responder,
)
from .ratchet import (
    DoubleRatchet,
    ChainKey,
    MAX_CHAIN_MESSAGES,
    MAX_SKIPPED_MESSAGES,
)
from .session import (
    Session,
    SessionConfig,
)
from .safety_number import (
    SafetyNumber,
)
from .group import (
    GroupSession,
    SenderKey,
    SenderKeyMessage,
    MAX_GROUP_SIZE,
)

__all__ = [
    # Crypto primitives
    "Ed25519KeyPair",
    "X25519KeyPair",
    "random_bytes",
    "hkdf",
    "hmac_sha256",
    "sha256",
    "sha512",
    "chacha20_poly1305_encrypt",
    "chacha20_poly1305_decrypt",
    "derive_identity_keys",
    "KEY_LENGTH",
    "NONCE_LENGTH",
    # X3DH
    "PreKeyBundle",
    "X3DHResult",
    "x3dh_initiator",
    "x3dh_responder",
    # Double Ratchet
    "DoubleRatchet",
    "ChainKey",
    "MAX_CHAIN_MESSAGES",
    "MAX_SKIPPED_MESSAGES",
    # Session
    "Session",
    "SessionConfig",
    # Safety Numbers
    "SafetyNumber",
    # Group
    "GroupSession",
    "SenderKey",
    "SenderKeyMessage",
    "MAX_GROUP_SIZE",
    # Version
    "__version__",
]
