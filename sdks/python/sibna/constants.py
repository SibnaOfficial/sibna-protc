"""Sibna Protocol Python SDK — protocol constants.

All constants are normative and kept in sync with the Rust core (`core/`) and
the protocol specification (`PROTOCOL_SPECIFICATION.md`).

Where a constant is mirrored in Rust, changing it here MUST be accompanied by
the same change in Rust and a protocol-version bump (see `version_check.py`).
"""

from __future__ import annotations

# ── Protocol version ─────────────────────────────────────────────────────────
# Normative protocol version (package / specification).
PROTOCOL_VERSION_STRING = "3.0.2"

# Wire-format protocol version (see PROTOCOL_SPECIFICATION.md §8).
PROTOCOL_VERSION_WIRE = 10
MIN_COMPATIBLE_VERSION = 9

# ── Key sizes ────────────────────────────────────────────────────────────────
KEY_LENGTH = 32  # 256-bit keys (X25519 / Ed25519 / ChaCha20 / HKDF output)
ED25519_PUBLIC_KEY_LENGTH = 32
NONCE_LENGTH = 12  # ChaCha20-Poly1305 nonce (96 bits)
TAG_LENGTH = 16  # Poly1305 tag (128 bits)
ED25519_SIGNATURE_LENGTH = 64
X25519_PUBLIC_KEY_LENGTH = 32
ML_KEM_768_PUBLIC_KEY_LENGTH = 1184  # FIPS 203
ML_KEM_768_SECRET_KEY_LENGTH = 2400  # FIPS 203
ML_KEM_768_CIPHERTEXT_LENGTH = 1088  # FIPS 203
ML_KEM_768_SHARED_SECRET_LENGTH = 32  # FIPS 203
SAFETY_NUMBER_FINGERPRINT_LENGTH = 32
SAFETY_NUMBER_DIGIT_COUNT = 80

# ── Ratchet limits ───────────────────────────────────────────────────────────
MAX_SKIPPED_MESSAGES = 2000
MAX_CHAIN_MESSAGES = 4000
MAX_MESSAGE_NUMBER = 1_000_000_000_000
MAX_MESSAGE_AGE_SECS = 86_400  # 24 hours (ratchet header timestamp)
MAX_TIMESTAMP_FUTURE_SECS = 300  # 5 minutes future tolerance (ratchet header)
MAX_AD_LEN = 256  # associated data (matches crypto layer)
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MiB
MAX_SESSION_ID_LEN = 256
MAX_PASSWORD_LEN = 256
MAX_GROUP_SIZE = 256
MAX_GROUP_MESSAGE_SIZE = 10 * 1024 * 1024

# ── Padding ──────────────────────────────────────────────────────────────────
PADDING_BLOCK_STANDARD = 1024
MAX_EXTRA_BLOCKS = 7  # SIBNA-2026-018
MAX_PADDING_BYTES = 65_535

# ── KDF / domain separation strings ──────────────────────────────────────────
# X3DH
X3DH_TRANSCRIPT_BIND_INFO = b"SibnaX3DH_TranscriptBind_v3"
X3DH_SHARED_SECRET_INFO = b"SibnaX3DH_v3"
X3DH_PQ_SHARED_SECRET_INFO = b"SibnaPQX3DH_v3"
SPK_SIGN_DOMAIN = b"SibnaSignedPreKey_v3"

# Double Ratchet
INITIAL_KDF_SALT = b"SibnaSession_v3"
INITIAL_KDF_INFO = b"SibnaRootAndChainKey_v3"
DH_RATCHET_INFO = b"SibnaRatchet_v3"

# Chain-key seeds (HMAC-SHA256)
MESSAGE_KEY_SEED = b"\x01"
CHAIN_KEY_SEED = b"\x02"
HEADER_KEY_SEED = b"\x03"

# Group
GROUP_MESSAGE_KEY_INFO = b"SibnaGroupMessageKey_v3"
GROUP_CHAIN_KEY_INFO = b"SibnaGroupChainKey_v3"
GROUP_KEY_DISTRIBUTE_INFO = b"SibnaGroupKeyDistribute_v3"

# Safety number
SAFETY_NUMBER_DOMAIN = b"SIBNA_SAFETY_NUMBER_V1"
SAFETY_NUMBER_DOMAIN_EXTRA = b"SIBNA_SAFETY_NUMBER_V1_EXTRA"
SAFETY_NUMBER_VERSION = 1

# Storage
STORAGE_AEAD_CONTEXT = b"SibnaUnifiedStore_v1"
KEYSTORE_AEAD_CONTEXT = b"SibnaKeyStore_v3"
SALT_HEADER = b"SIBNA_SALT_V1"
STORAGE_MAGIC = b"SIBNA001"

# ── Device / envelope ────────────────────────────────────────────────────────
DEVICE_ID_LENGTH = 16
ENVELOPE_MAX_AGE_SECS = 300  # signed envelope freshness (5 minutes)
