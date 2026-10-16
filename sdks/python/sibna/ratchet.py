"""
Sibna Protocol v3.0.1 — Double Ratchet.

Wire-compatible with the Rust core (`core/src/ratchet/`).

Encrypt wire format (plaintext header, v3.0 default — matches Rust
`RatchetMessage::to_bytes`):

    dh_public(32) || message_number(8 LE) || previous_chain_length(8 LE) ||
    timestamp(8 LE) || nonce(12) || ciphertext || tag(16)

That is: RatchetHeader(56 bytes) || Encryptor output
         (nonce(12) || ciphertext || tag(16)).

Encrypted header (v3.1, `enable_header_encryption`):

    nonce(12) || ChaCha20-Poly1305(header)(56) || tag(16) || ciphertext(...)

Associated data: caller AD || header_bytes.

Double Ratchet KDFs match Rust `core/src/crypto/kdf.rs`:

    KDF_RK(root_key, dh_out) = HKDF(salt=root_key, ikm=dh_out,
                                     info="SibnaRatchet_v3", len=64)
        -> [root_key(32)][chain_key(32)]
    KDF_CK(chain_key):
        message_key   = HMAC-SHA256(chain_key, 0x01)
        next_chain_key= HMAC-SHA256(chain_key, 0x02)
    header_key        = HMAC-SHA256(chain_key, 0x03)

Initial session from X3DH shared secret:

    OKM = HKDF(salt="SibnaSession_v3", ikm=shared_secret,
               info="SibnaRootAndChainKey_v3", len=64)
    root_key   = OKM[:32]
    chain_key  = OKM[32:]

Skipped-message-key cache: up to MAX_SKIPPED_MESSAGES (2000) entries,
keyed by (remote_dh_public, message_number), single-use, evicted oldest-first.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from . import constants as C
from .crypto import (
    X25519KeyPair,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    hkdf,
    hmac_sha256,
    random_bytes,
)
from .errors import CryptoError, ProtocolError, ValidationError

MESSAGE_KEY_SEED = b"\x01"
CHAIN_KEY_SEED = b"\x02"
HEADER_KEY_SEED = b"\x03"
HANDSHAKE_OK_AD = b"OK"
HANDSHAKE_OK_AD = b"OK"

HEADER_SIZE = 56  # dh_public(32) || message_number(8) || prev_len(8) || timestamp(8)


@dataclass
class ChainKey:
    """Symmetric ratchet chain key."""

    key: bytes
    index: int = 0
    created_at: float = field(default_factory=time.time)
    max_messages: int = C.MAX_CHAIN_MESSAGES

    def next_message_key(self) -> Optional[Tuple[bytes, "ChainKey"]]:
        """Derive next message key and advance the chain."""
        if self.index >= self.max_messages:
            return None
        message_key = hmac_sha256(self.key, MESSAGE_KEY_SEED)
        next_chain = hmac_sha256(self.key, CHAIN_KEY_SEED)
        return message_key, ChainKey(
            key=next_chain,
            index=self.index + 1,
            created_at=self.created_at,
            max_messages=self.max_messages,
        )

    def derive_header_key(self) -> bytes:
        return hmac_sha256(self.key, HEADER_KEY_SEED)

    def remaining_messages(self) -> int:
        return max(0, self.max_messages - self.index)


class DoubleRatchet:
    """
    Double Ratchet encryption state machine.

    Manages root_key, sending/receiving chains, DH pairs, skipped-message-key
    cache, and replay protection. Wire-compatible with the Rust core.
    """

    def __init__(
        self,
        root_key: bytes,
        sending_chain: Optional[ChainKey] = None,
        receiving_chain: Optional[ChainKey] = None,
        dh_local_private: Optional[bytes] = None,
        dh_local_public: Optional[bytes] = None,
        dh_remote_public: Optional[bytes] = None,
        previous_counter: int = 0,
        max_skip: int = C.MAX_SKIPPED_MESSAGES,
    ):
        if len(root_key) != C.KEY_LENGTH:
            raise ValidationError("root_key must be 32 bytes")
        self.root_key = root_key
        self.sending_chain = sending_chain
        self.receiving_chain = receiving_chain
        self.dh_local_private = dh_local_private
        self.dh_local_public = dh_local_public
        self.dh_remote_public = dh_remote_public
        self.previous_counter = previous_counter
        self.max_skip = max_skip
        self.skipped_keys: Dict[Tuple[bytes, int], bytes] = {}
        self.messages_sent = 0
        self.messages_received = 0
        self.created_at = time.time()
        self.last_activity = time.time()

    @classmethod
    def from_shared_secret(
        cls,
        shared_secret: bytes,
        local_dh_private: bytes,
        remote_dh_public: bytes,
        role_is_initiator: bool,
    ) -> "DoubleRatchet":
        """Create initial DoubleRatchet state from X3DH shared secret."""
        if len(shared_secret) != C.KEY_LENGTH:
            raise ValidationError("shared_secret must be 32 bytes")
        if len(local_dh_private) != C.KEY_LENGTH:
            raise ValidationError("local_dh_private must be 32 bytes")
        if len(remote_dh_public) != C.KEY_LENGTH:
            raise ValidationError("remote_dh_public must be 32 bytes")

        okm = hkdf(
            shared_secret,
            salt=C.INITIAL_KDF_SALT,
            info=C.INITIAL_KDF_INFO,
            length=64,
        )
        root_key = okm[:32]
        chain_key = okm[32:]

        local_pub = X25519KeyPair.from_private_bytes(local_dh_private).public_key

        if role_is_initiator:
            sending = ChainKey(key=chain_key)
            receiving = None
        else:
            sending = None
            receiving = ChainKey(key=chain_key)

        return cls(
            root_key=root_key,
            sending_chain=sending,
            receiving_chain=receiving,
            dh_local_private=local_dh_private,
            dh_local_public=local_pub,
            dh_remote_public=remote_dh_public,
        )

    # ── Root key KDF ──────────────────────────────────────────────────

    def _kdf_rk(self, dh_out: bytes) -> Tuple[bytes, bytes]:
        okm = hkdf(
            dh_out,
            salt=self.root_key,
            info=C.DH_RATCHET_INFO,
            length=64,
        )
        return okm[:32], okm[32:]

    # ── DH Ratchet step ───────────────────────────────────────────────

    def _dh_ratchet_step(self) -> None:
        if self.receiving_chain is not None:
            self.previous_counter = self.receiving_chain.index

        assert self.dh_local_private is not None
        assert self.dh_remote_public is not None
        existing_local = X25519KeyPair.from_private_bytes(self.dh_local_private)
        dh_out_recv = existing_local.dh(self.dh_remote_public)
        self.root_key, receiving_chain_key = self._kdf_rk(dh_out_recv)
        self.receiving_chain = ChainKey(key=receiving_chain_key)

        new_local = X25519KeyPair.generate()
        self.dh_local_private = new_local.private_key_bytes
        self.dh_local_public = new_local.public_key
        assert self.dh_remote_public is not None
        dh_out_send = new_local.dh(self.dh_remote_public)
        self.root_key, sending_chain_key = self._kdf_rk(dh_out_send)
        self.sending_chain = ChainKey(key=sending_chain_key)

    # ── Skipped keys ──────────────────────────────────────────────────

    def _try_skipped_message_key(self, dh_public: bytes, message_number: int) -> Optional[bytes]:
        key = (dh_public, message_number)
        if key in self.skipped_keys:
            mk = self.skipped_keys.pop(key)
            return mk
        return None

    def _skip_message_keys(self, until: int) -> None:
        if self.receiving_chain is None:
            return
        while self.receiving_chain.index < until:
            result = self.receiving_chain.next_message_key()
            if result is None:
                break
            mk, next_ck = result
            assert self.dh_remote_public is not None
            self.skipped_keys[(self.dh_remote_public, self.receiving_chain.index)] = mk
            if len(self.skipped_keys) > self.max_skip:
                oldest_key = next(iter(self.skipped_keys))
                del self.skipped_keys[oldest_key]
            self.receiving_chain = next_ck

    # ── Transactional state copy ──────────────────────────────────────

    def _clone_for_decrypt(self) -> "DoubleRatchet":
        """Create an isolated copy of ratchet state for transactional decryption.

        ChainKey objects are immutable once created: ``next_message_key()``
        returns a new instance rather than mutating in place, so sharing
        references between the original and the clone is safe.  The
        ``skipped_keys`` dict is shallow-copied so that a partial consumption
        during a failed decryption attempt does not affect the live state.
        """
        clone = DoubleRatchet(
            root_key=self.root_key,
            sending_chain=self.sending_chain,
            receiving_chain=self.receiving_chain,
            dh_local_private=self.dh_local_private,
            dh_local_public=self.dh_local_public,
            dh_remote_public=self.dh_remote_public,
            previous_counter=self.previous_counter,
            max_skip=self.max_skip,
        )
        clone.skipped_keys = dict(self.skipped_keys)
        clone.messages_sent = self.messages_sent
        clone.messages_received = self.messages_received
        clone.created_at = self.created_at
        clone.last_activity = self.last_activity
        return clone

    # ── Encrypt ───────────────────────────────────────────────────────

    def ratchet_encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """Encrypt using the sending chain.

        Wire format (matches Rust ``RatchetMessage::to_bytes``):

            header(56) || encryptor_frame(...)

        header  = dh_public(32) || message_number(8 LE)
                  || previous_chain_length(8 LE) || timestamp(8 LE)

        encryptor_frame = message_number(8 LE) || timestamp(8 LE)
                          || padding(8 LE) || nonce(12) || ciphertext || tag(16)

        Associated data = caller AD || header.
        """
        if len(associated_data) > C.MAX_AD_LEN:
            raise ValidationError("Associated data too long")

        if self.sending_chain is None:
            if self.dh_remote_public is None:
                raise CryptoError("No remote DH public key")
            new_local = X25519KeyPair.generate()
            self.dh_local_private = new_local.private_key_bytes
            self.dh_local_public = new_local.public_key
            dh_out = new_local.dh(self.dh_remote_public)
            self.root_key, sending_chain_key = self._kdf_rk(dh_out)
            self.sending_chain = ChainKey(key=sending_chain_key)

        msg_num = self.sending_chain.index
        result = self.sending_chain.next_message_key()
        if result is None:
            raise CryptoError("Chain exhausted")
        message_key, next_ck = result
        self.sending_chain = next_ck
        self.messages_sent += 1

        assert self.dh_local_public is not None
        timestamp = int(time.time())
        header = (
            self.dh_local_public
            + struct.pack("<Q", msg_num)
            + struct.pack("<Q", self.previous_counter)
            + struct.pack("<Q", timestamp)
        )
        if len(header) != HEADER_SIZE:
            raise CryptoError("Header size mismatch")

        nonce = random_bytes(C.NONCE_LENGTH)
        # Encryptor frame header: message_number(8) || timestamp(8) || padding(8).
        # This is part of the AEAD associated data, matching the Rust Encryptor.
        frame_header = (
            struct.pack("<Q", 0)  # encryptor message_number (fresh per message)
            + struct.pack("<Q", timestamp)
            + struct.pack("<Q", 0)  # padding (Rust always writes 0)
        )
        full_ad = associated_data + header + frame_header
        ct_and_tag = chacha20_poly1305_encrypt(
            message_key, plaintext, full_ad, nonce
        )  # nonce(12) || ciphertext || tag(16)

        frame = frame_header + ct_and_tag

        self.last_activity = time.time()
        return header + frame

    # ── Decrypt ───────────────────────────────────────────────────────

    def ratchet_decrypt(self, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        if len(associated_data) > C.MAX_AD_LEN:
            raise ValidationError("Associated data too long")
        # header(56) + frame_min(8+8+8+12+16)
        if len(ciphertext) < HEADER_SIZE + 52:
            raise CryptoError("Ciphertext too short")

        remote_dh_pub = ciphertext[: C.KEY_LENGTH]
        msg_num = struct.unpack("<Q", ciphertext[C.KEY_LENGTH : C.KEY_LENGTH + 8])[0]
        previous_chain_length = struct.unpack(
            "<Q", ciphertext[C.KEY_LENGTH + 8 : C.KEY_LENGTH + 16]
        )[0]
        timestamp = struct.unpack("<Q", ciphertext[C.KEY_LENGTH + 16 : C.KEY_LENGTH + 24])[0]
        frame = ciphertext[HEADER_SIZE:]

        self._validate_timestamp(timestamp)

        # Transactional: perform all state mutations on an isolated clone.
        # Commit to the live state only after ChaCha20-Poly1305 authentication
        # succeeds.  On any failure the clone is discarded and the live state
        # is unchanged.
        candidate = self._clone_for_decrypt()

        mk = candidate._try_skipped_message_key(remote_dh_pub, msg_num)
        if mk is None:
            if remote_dh_pub != candidate.dh_remote_public:
                candidate.receiving_chain = None
                candidate.skipped_keys.clear()
                candidate.dh_remote_public = remote_dh_pub
                candidate._dh_ratchet_step()

            if candidate.receiving_chain is not None:
                candidate._skip_message_keys(msg_num)
                result = candidate.receiving_chain.next_message_key()
                if result is None:
                    raise CryptoError("Receiving chain exhausted")
                mk, next_ck = result
                candidate.receiving_chain = next_ck
            else:
                raise CryptoError("No receiving chain")

        header = (
            remote_dh_pub
            + struct.pack("<Q", msg_num)
            + struct.pack("<Q", previous_chain_length)
            + struct.pack("<Q", timestamp)
        )

        # frame: frame_header(24) || nonce(12) || ciphertext || tag(16)
        frame_header = frame[:24]
        nonce = frame[24 : 24 + C.NONCE_LENGTH]
        ct_and_tag = frame[24 + C.NONCE_LENGTH :]

        # full_ad = caller AD || header(56) || frame_header(24)
        full_ad = associated_data + header + frame_header

        try:
            plaintext = chacha20_poly1305_decrypt(
                mk,
                nonce + ct_and_tag,
                full_ad,
            )  # verify authentication; plaintext is the message payload
        except Exception as exc:
            raise CryptoError("Decryption failed") from exc

        # Commit candidate state only after successful authentication.
        candidate.messages_received += 1
        candidate.last_activity = time.time()
        self.root_key = candidate.root_key
        self.sending_chain = candidate.sending_chain
        self.receiving_chain = candidate.receiving_chain
        self.dh_local_private = candidate.dh_local_private
        self.dh_local_public = candidate.dh_local_public
        self.dh_remote_public = candidate.dh_remote_public
        self.previous_counter = candidate.previous_counter
        self.skipped_keys = candidate.skipped_keys
        self.messages_received = candidate.messages_received
        self.last_activity = candidate.last_activity

        return plaintext

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _validate_timestamp(timestamp: int) -> None:
        now = int(time.time())
        if timestamp == 0:
            raise CryptoError("Rejected timestamp == 0")
        if timestamp > now + C.MAX_TIMESTAMP_FUTURE_SECS:
            raise CryptoError("Timestamp in the future")
        if now > timestamp + C.MAX_MESSAGE_AGE_SECS:
            raise CryptoError("Message too old")

    def validate_message_number(self, n: int) -> None:
        if n > C.MAX_MESSAGE_NUMBER:
            raise ProtocolError("Message number exceeds limit")

    @property
    def current_message_number(self) -> int:
        return self.messages_sent + self.messages_received


__all__ = [
    "ChainKey",
    "DoubleRatchet",
    "HEADER_SIZE",
    "ProtocolError",
]
