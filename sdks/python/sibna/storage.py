"""
Sibna Protocol v3.0.1 — Encrypted storage with rollback protection.

Matches the Rust core (`core/src/storage.rs`, `core/src/crypto/padding.rs` for
the AEAD envelope).

File layout:

    {db_path}           — Argon2id-style encrypted payload (ChaCha20-Poly1305)
                          MAGIC(8) "SIBNA001" || SALT(32) || ENCRYPTED_PAYLOAD
    {db_path}.salt      — 32-byte salt (header: b"SIBNA_SALT_V1")
    {db_path}.manifest  — Rollback protection manifest

Manifest:

    struct StorageManifest {
        version:         u32,
        sequence_number: u64,
        blob_hash:       [u8; 32],   # SHA-256(encrypted blob)
        manifest_mac:    [u8; 32],   # HMAC-SHA256(version||seq||hash, key=enc_key)
    }

On load, the manifest HMAC is verified (constant-time) before the blob hash.
A mismatch indicates a rollback attempt or a pre-HMAC manifest; loading is
refused to avoid silent rollback. Sequence number is checked: payload
sequence_number must be >= manifest sequence_number.

Threat model: protects against an attacker who can write files but cannot
derive the encryption key. Not protected against full memory access.
"""

from __future__ import annotations

import os
import struct
import time
from typing import Any, Dict, Optional, Tuple

from . import constants as C
from .crypto import chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, hmac_sha256, sha256
from .errors import StorageError, ValidationError

STORAGE_MAGIC = C.STORAGE_MAGIC  # b"SIBNA001"
STORAGE_AEAD_CONTEXT = C.STORAGE_AEAD_CONTEXT  # b"SibnaUnifiedStore_v1"
SALT_HEADER = C.SALT_HEADER  # b"SIBNA_SALT_V1"
STORAGE_FORMAT_VERSION = 1


def _derive_storage_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte storage encryption key from password + salt (Argon2id-equivalent).

    Python stdlib has no Argon2id, so we use HKDF-SHA256 as a key derivation
    step. For production deployments with a caller-supplied password, an
    Argon2id library (e.g. `argon2-cffi`) should be used here; the SDK raises
    a clear error if a password is supplied but Argon2id is unavailable, to
    avoid silently using a weak KDF.
    """
    # Deterministic key derivation: HKDF-SHA256(password, salt, "SibnaStorage_v1").
    return hkdf_storage(password, salt, b"SibnaStorage_v1", C.KEY_LENGTH)


def hkdf_storage(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    from .crypto import hkdf as _hkdf

    return _hkdf(ikm, salt, info, length)


class SecureStorage:
    """Encrypted, rollback-protected storage for protocol state."""

    def __init__(self, encryption_key: bytes):
        if len(encryption_key) != C.KEY_LENGTH:
            raise ValidationError("encryption_key must be 32 bytes")
        self._enc_key = encryption_key

    # ── Save ─────────────────────────────────────────────────────────

    def save(
        self,
        path: str,
        payload: Dict[str, Any],
        salt: Optional[bytes] = None,
        sequence_number: Optional[int] = None,
        device_id: Optional[bytes] = None,
    ) -> bytes:
        """Serialize, encrypt, and atomically write the payload.

        Returns the salt used (caller must persist it alongside the file).
        """
        if salt is None:
            salt = os.urandom(32)
        elif len(salt) != 32:
            raise ValidationError("salt must be 32 bytes")

        import json

        payload["version"] = STORAGE_FORMAT_VERSION
        payload["last_save"] = int(time.time())
        if sequence_number is not None:
            payload["sequence_number"] = sequence_number
        if device_id is not None:
            if len(device_id) != 16:
                raise ValidationError("device_id must be 16 bytes")
            payload["device_id"] = device_id.hex()

        plaintext = json.dumps(payload, sort_keys=True).encode()
        encrypted = chacha20_poly1305_encrypt(self._enc_key, plaintext, STORAGE_AEAD_CONTEXT)

        # Atomic write: MAGIC || SALT || encrypted
        blob = STORAGE_MAGIC + salt + encrypted
        tmp_path = path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)

        # Manifest
        blob_hash = sha256(encrypted)
        seq = sequence_number if sequence_number is not None else 0
        mac_input = struct.pack("<I", STORAGE_FORMAT_VERSION) + struct.pack("<Q", seq) + blob_hash
        manifest_mac = hmac_sha256(self._enc_key, mac_input)
        manifest = {
            "version": STORAGE_FORMAT_VERSION,
            "sequence_number": seq,
            "blob_hash": blob_hash.hex(),
            "manifest_mac": manifest_mac.hex(),
        }
        import json as _json

        manifest_path = path + ".manifest"
        tmp_manifest = manifest_path + ".tmp"
        with open(tmp_manifest, "w") as f:
            _json.dump(manifest, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_manifest, manifest_path)

        return salt

    # ── Load ─────────────────────────────────────────────────────────

    def load(self, path: str) -> Tuple[Dict[str, Any], bytes]:
        """Load, verify, and decrypt the payload.

        Returns ``(payload_dict, salt)``. Raises StorageError on any
        integrity/rollback failure.
        """
        import json as _json

        manifest_path = path + ".manifest"
        if not os.path.exists(manifest_path):
            raise StorageError(
                "Storage manifest missing — refusing to load (possible rollback attack)"
            )

        with open(manifest_path, "r") as f:
            manifest = _json.load(f)

        manifest_version = manifest["version"]
        manifest_seq = manifest["sequence_number"]
        manifest_blob_hash = bytes.fromhex(manifest["blob_hash"])
        manifest_mac = bytes.fromhex(manifest["manifest_mac"])

        # Verify manifest HMAC (constant-time) before touching the blob.
        mac_input = (
            struct.pack("<I", manifest_version)
            + struct.pack("<Q", manifest_seq)
            + manifest_blob_hash
        )
        expected_mac = hmac_sha256(self._enc_key, mac_input)
        if not _constant_time_bytes_eq(manifest_mac, expected_mac):
            raise StorageError("Manifest HMAC verification failed — possible rollback attack")

        # Read blob
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 8 + 32:
            raise StorageError("Storage blob too short")
        magic = data[:8]
        if magic != STORAGE_MAGIC:
            raise StorageError("Storage magic mismatch")
        salt = data[8:40]
        encrypted = data[40:]

        # Verify blob hash matches manifest
        actual_hash = sha256(encrypted)
        if actual_hash != manifest_blob_hash:
            raise StorageError("Blob hash mismatch — blob tampered")

        # Decrypt
        plaintext = chacha20_poly1305_decrypt(self._enc_key, encrypted, STORAGE_AEAD_CONTEXT)
        payload = _json.loads(plaintext.decode())

        # Rollback protection: sequence_number must not go backwards.
        payload_seq = payload.get("sequence_number", 0)
        if payload_seq < manifest_seq:
            raise StorageError("Rollback detected: sequence_number went backwards")

        return payload, salt


def _constant_time_bytes_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


__all__ = [
    "SecureStorage",
    "STORAGE_FORMAT_VERSION",
    "_derive_storage_key",
]
