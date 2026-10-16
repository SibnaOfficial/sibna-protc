"""
Sibna Protocol — Python SDK v3.0.1 (sole official SDK).

Pure-Python implementation of the Sibna Protocol (X3DH handshake, Double
Ratchet session encryption, sender-key group messaging, safety numbers,
envelope signing, encrypted storage, and the relay HTTP/WebSocket client).

No Rust core, FFI, or native library required. All cryptography is provided by
maintained libraries (`cryptography`, `blake3`, `pqcrypto`).

Wire formats, domain-separation strings, KDF constructions, and limits match
the retained Rust core (`core/`) and `PROTOCOL_SPECIFICATION.md`.

Install:
    pip install sibna
"""

from __future__ import annotations

__version__ = "3.0.1"
__author__ = "Sibna Security Team"
__license__ = "Apache-2.0 OR MIT"

# ── Constants ────────────────────────────────────────────────────────────────
from .constants import (  # noqa: F401
    ED25519_PUBLIC_KEY_LENGTH,
    GROUP_CHAIN_KEY_INFO,
    GROUP_KEY_DISTRIBUTE_INFO,
    GROUP_MESSAGE_KEY_INFO,
    KEY_LENGTH,
    MAX_AD_LEN,
    MAX_CHAIN_MESSAGES,
    MAX_EXTRA_BLOCKS,
    MAX_GROUP_MESSAGE_SIZE,
    MAX_GROUP_SIZE,
    MAX_MESSAGE_AGE_SECS,
    MAX_MESSAGE_NUMBER,
    MAX_MESSAGE_SIZE,
    MAX_PASSWORD_LEN,
    MAX_PADDING_BYTES,
    MAX_SESSION_ID_LEN,
    MAX_SKIPPED_MESSAGES,
    ML_KEM_768_CIPHERTEXT_LENGTH,
    ML_KEM_768_PUBLIC_KEY_LENGTH,
    ML_KEM_768_SECRET_KEY_LENGTH,
    MIN_COMPATIBLE_VERSION,
    NONCE_LENGTH,
    PADDING_BLOCK_STANDARD,
    PROTOCOL_VERSION_STRING,
    PROTOCOL_VERSION_WIRE,
    SAFETY_NUMBER_DIGIT_COUNT,
    TAG_LENGTH,
    X25519_PUBLIC_KEY_LENGTH,
)

# ── Errors ───────────────────────────────────────────────────────────────────
from .errors import (  # noqa: F401
    AuthError,
    CryptoError,
    KeyNotFoundError,
    NetworkError,
    ProtocolError,
    SessionNotFoundError,
    SibnaError,
    StorageError,
    ValidationError,
)

# ── Cryptographic primitives ─────────────────────────────────────────────────
from .crypto import (  # noqa: F401
    C,
    X25519KeyPair,
    Ed25519KeyPair,
    blake3_hash,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    derive_identity_keys,
    hmac_sha256,
    hkdf,
    hkdf_expand,
    hkdf_extract,
    ml_kem_768_decapsulate,
    ml_kem_768_encapsulate,
    ml_kem_768_keypair,
    random_bytes,
    sha256,
    sha512,
)

# ── Padding ──────────────────────────────────────────────────────────────────
from .padding import (  # noqa: F401
    PaddingMode,
    pad_message,
    pad_payload,
    unpad_message,
    unpad_payload,
)

# ── X3DH ─────────────────────────────────────────────────────────────────────
from .x3dh import (  # noqa: F401
    PreKeyBundle,
    X3DHResult,
    generate_peer_bundle,
    x3dh_initiator,
    x3dh_responder,
)

# ── Double Ratchet ──────────────────────────────────────────────────────────
from .ratchet import (  # noqa: F401
    ChainKey,
    DoubleRatchet,
    HEADER_SIZE,
)

# ── Session ──────────────────────────────────────────────────────────────────
from .session import (  # noqa: F401
    Session,
    SessionConfig,
)

# ── Group messaging ──────────────────────────────────────────────────────────
from .group import (  # noqa: F401
    GroupMessage,
    GroupSession,
    SenderKey,
    SenderKeyMessage,
    MAX_GROUP_MESSAGE_SIZE as _MAX_GROUP_MESSAGE_SIZE,  # noqa: F401
    MAX_GROUP_SIZE as _MAX_GROUP_SIZE,  # noqa: F401
)

# ── Safety numbers ───────────────────────────────────────────────────────────
from .safety_number import (  # noqa: F401
    SafetyNumber,
    SAFETY_NUMBER_DIGIT_COUNT as _SAFETY_NUMBER_DIGIT_COUNT,  # noqa: F401
    SAFETY_NUMBER_VERSION as _SAFETY_NUMBER_VERSION,  # noqa: F401
)

# ── Envelope ─────────────────────────────────────────────────────────────────
from .envelope import (  # noqa: F401
    ENVELOPE_MAX_AGE_SECS as _ENVELOPE_MAX_AGE_SECS,  # noqa: F401
    make_signed_envelope,
    verify_signed_envelope,
)

# ── Storage ──────────────────────────────────────────────────────────────────
from .storage import (  # noqa: F401
    SecureStorage,
    STORAGE_FORMAT_VERSION as _STORAGE_FORMAT_VERSION,  # noqa: F401
)

# ── Relay client ─────────────────────────────────────────────────────────────
from .client import (  # noqa: F401
    AsyncSibnaClient,
    Identity,
    SibnaClient,
)

__all__ = [
    # Version
    "__version__",
    # Constants
    "KEY_LENGTH",
    "ED25519_PUBLIC_KEY_LENGTH",
    "NONCE_LENGTH",
    "TAG_LENGTH",
    "MAX_AD_LEN",
    "MAX_CHAIN_MESSAGES",
    "MAX_EXTRA_BLOCKS",
    "MAX_GROUP_MESSAGE_SIZE",
    "MAX_GROUP_SIZE",
    "MAX_MESSAGE_AGE_SECS",
    "MAX_MESSAGE_NUMBER",
    "MAX_MESSAGE_SIZE",
    "MAX_PASSWORD_LEN",
    "MAX_PADDING_BYTES",
    "MAX_SESSION_ID_LEN",
    "MAX_SKIPPED_MESSAGES",
    "ML_KEM_768_CIPHERTEXT_LENGTH",
    "ML_KEM_768_PUBLIC_KEY_LENGTH",
    "ML_KEM_768_SECRET_KEY_LENGTH",
    "MIN_COMPATIBLE_VERSION",
    "PADDING_BLOCK_STANDARD",
    "PROTOCOL_VERSION_STRING",
    "PROTOCOL_VERSION_WIRE",
    "SAFETY_NUMBER_DIGIT_COUNT",
    "X25519_PUBLIC_KEY_LENGTH",
    # Errors
    "SibnaError",
    "AuthError",
    "CryptoError",
    "ValidationError",
    "ProtocolError",
    "NetworkError",
    "StorageError",
    "KeyNotFoundError",
    "SessionNotFoundError",
    # Crypto
    "X25519KeyPair",
    "Ed25519KeyPair",
    "blake3_hash",
    "sha256",
    "sha512",
    "hkdf",
    "hkdf_extract",
    "hkdf_expand",
    "hmac_sha256",
    "random_bytes",
    "derive_identity_keys",
    "chacha20_poly1305_encrypt",
    "chacha20_poly1305_decrypt",
    "ml_kem_768_keypair",
    "ml_kem_768_encapsulate",
    "ml_kem_768_decapsulate",
    # Padding
    "PaddingMode",
    "pad_message",
    "pad_payload",
    "unpad_message",
    "unpad_payload",
    # X3DH
    "PreKeyBundle",
    "X3DHResult",
    "generate_peer_bundle",
    "x3dh_initiator",
    "x3dh_responder",
    # Double Ratchet
    "ChainKey",
    "DoubleRatchet",
    "HEADER_SIZE",
    # Session
    "Session",
    "SessionConfig",
    # Group
    "SenderKey",
    "SenderKeyMessage",
    "GroupMessage",
    "GroupSession",
    # Safety Numbers
    "SafetyNumber",
    # Envelope
    "make_signed_envelope",
    "verify_signed_envelope",
    # Storage
    "SecureStorage",
    # Relay client
    "Identity",
    "SibnaClient",
    "AsyncSibnaClient",
]
