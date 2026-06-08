"""
Sibna Protocol v3.0.1 — Double Ratchet Implementation

Matches the Rust core exactly:
  - ChainKey derivation: HMAC-SHA256(chain_key, 0x01) = message_key,
                         HMAC-SHA256(chain_key, 0x02) = next_chain_key
  - Root key KDF: HKDF(root_key, dh_output, "SibnaRatchet_v3")
  - Initial session KDF: HKDF(shared_secret, salt="SibnaSession_v3",
                               info="SibnaRootAndChainKey_v3")
  - Encryptor wire format: msg_number(8) || timestamp(8) || nonce(12) || ciphertext+tag
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from .crypto import (
    KEY_LENGTH,
    NONCE_LENGTH,
    TAG_LENGTH,
    X25519KeyPair,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    hkdf,
    hmac_sha256,
    random_bytes,
)

# ── Chain Key ────────────────────────────────────────────────────────────────

MESSAGE_KEY_SEED = bytes([0x01])
CHAIN_KEY_SEED = bytes([0x02])
HEADER_KEY_SEED = bytes([0x03])

INITIAL_KDF_SALT = b"SibnaSession_v3"
INITIAL_KDF_INFO = b"SibnaRootAndChainKey_v3"
DH_RATCHET_INFO = b"SibnaRatchet_v3"

MAX_CHAIN_MESSAGES = 4000
MAX_SKIPPED_MESSAGES = 2000


@dataclass
class ChainKey:
    """Symmetric ratchet chain key."""

    key: bytes
    index: int = 0
    created_at: float = field(default_factory=time.time)
    max_messages: int = MAX_CHAIN_MESSAGES

    def next_message_key(self) -> Optional[Tuple[bytes, "ChainKey"]]:
        """
        Derive the next message key and advance the chain.
        Returns (message_key, next_chain_key) or None if chain exhausted.
        """
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


# ── Double Ratchet Session ──────────────────────────────────────────────────


class DoubleRatchet:
    """
    Double Ratchet encryption state machine.

    Manages root_key, sending_chain, receiving_chain, DH key pairs,
    and skipped message key cache for out-of-order delivery.
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
        max_skip: int = MAX_SKIPPED_MESSAGES,
    ):
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
        """
        Create initial DoubleRatchet state from X3DH shared secret.
        Matches Rust DoubleRatchetSession::from_shared_secret().
        """
        if len(shared_secret) != KEY_LENGTH:
            raise ValueError("shared_secret must be 32 bytes")

        okm = hkdf(
            shared_secret,
            salt=INITIAL_KDF_SALT,
            info=INITIAL_KDF_INFO,
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

    # ── Root key KDF ────────────────────────────────────────────────────

    def _kdf_rk(self, dh_out: bytes) -> Tuple[bytes, bytes]:
        """KDF_RK: derive new root_key and chain_key from DH output."""
        okm = hkdf(
            dh_out,
            salt=self.root_key,
            info=DH_RATCHET_INFO,
            length=64,
        )
        return okm[:32], okm[32:]

    # ── DH Ratchet ──────────────────────────────────────────────────────

    def _dh_ratchet_step(self) -> None:
        """
        Perform a DH ratchet step when a new remote key is received.
        Matches Signal Double Ratchet spec exactly:

        1. Receive step: DH(existing_local_priv, new_remote_pub) → root + receiving_chain
        2. Send step: generate new_local, DH(new_local_priv, new_remote_pub) → root + sending_chain
        """
        # Save previous receiving chain for skipped key tracking
        if self.receiving_chain is not None:
            self.previous_counter = self.receiving_chain.index

        # --- Receive step: use EXISTING local key ---
        # This is critical: Alice uses her current private key (eph key) to DH with Bob's new key
        existing_local = X25519KeyPair.from_private_bytes(self.dh_local_private)
        dh_out_recv = existing_local.dh(self.dh_remote_public)
        self.root_key, receiving_chain_key = self._kdf_rk(dh_out_recv)
        self.receiving_chain = ChainKey(key=receiving_chain_key)

        # --- Send step: generate new key pair for future sends ---
        new_local = X25519KeyPair.generate()
        self.dh_local_private = new_local.private_key_bytes
        self.dh_local_public = new_local.public_key
        dh_out_send = new_local.dh(self.dh_remote_public)
        self.root_key, sending_chain_key = self._kdf_rk(dh_out_send)
        self.sending_chain = ChainKey(key=sending_chain_key)

    # ── Try skipped keys ────────────────────────────────────────────────

    def _try_skipped_message_key(
        self, dh_public: bytes, message_number: int
    ) -> Optional[bytes]:
        """Check if we have a skipped message key for this (pub, nr)."""
        key = (dh_public, message_number)
        if key in self.skipped_keys:
            mk = self.skipped_keys.pop(key)
            return mk
        return None

    def _skip_message_keys(self, until: int) -> None:
        """Skip message keys in the receiving chain until `until`."""
        if self.receiving_chain is None:
            return
        while self.receiving_chain.index < until:
            result = self.receiving_chain.next_message_key()
            if result is None:
                break
            mk, next_ck = result
            self.skipped_keys[
                (self.dh_remote_public, self.receiving_chain.index)
            ] = mk
            if len(self.skipped_keys) > self.max_skip:
                # Evict oldest entries
                oldest_key = next(iter(self.skipped_keys))
                del self.skipped_keys[oldest_key]
            self.receiving_chain = next_ck

    # ── Encrypt ─────────────────────────────────────────────────────────

    def ratchet_encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Encrypt a message using the sending chain.

        Wire format: dh_public(32) || message_number(4) || encrypted(12+msg+16)

        If no sending chain exists (responder's first reply), generates a new
        DH key pair and performs a DH ratchet step to create one.
        """
        # If no sending chain, do a DH ratchet step to create one
        if self.sending_chain is None:
            if self.dh_remote_public is None:
                raise RuntimeError("No remote DH public key")
            new_local = X25519KeyPair.generate()
            self.dh_local_private = new_local.private_key_bytes
            self.dh_local_public = new_local.public_key
            dh_out = new_local.dh(self.dh_remote_public)
            self.root_key, sending_chain_key = self._kdf_rk(dh_out)
            self.sending_chain = ChainKey(key=sending_chain_key)

        # Capture the message number BEFORE advancing the chain.
        # The message number is the chain index at the time of key derivation.
        msg_num = self.sending_chain.index

        result = self.sending_chain.next_message_key()
        if result is None:
            raise RuntimeError("Chain exhausted")
        message_key, next_ck = result
        self.sending_chain = next_ck

        self.messages_sent += 1

        # Build header: dh_public(32) + message_number(4 LE)
        header = self.dh_local_public + struct.pack("<I", msg_num & 0xFFFFFFFF)

        # Nonce: 8 bytes random + 4 bytes message_number LE
        nonce_prefix = os.urandom(8)
        nonce = nonce_prefix + struct.pack("<I", msg_num & 0xFFFFFFFF)

        # Associated data = caller's AD + header
        full_ad = associated_data + header

        ciphertext = chacha20_poly1305_encrypt(
            message_key, plaintext, full_ad, nonce
        )

        self.last_activity = time.time()
        return header + ciphertext

    # ── Decrypt ─────────────────────────────────────────────────────────

    def ratchet_decrypt(self, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Decrypt a message using the receiving chain.

        Wire format: dh_public(32) || message_number(4) || encrypted(12+msg+16)
        """
        if len(ciphertext) < KEY_LENGTH + 4 + NONCE_LENGTH + TAG_LENGTH:
            raise ValueError("Ciphertext too short")

        remote_dh_pub = ciphertext[:KEY_LENGTH]
        msg_num = struct.unpack("<I", ciphertext[KEY_LENGTH : KEY_LENGTH + 4])[0]
        encrypted_part = ciphertext[KEY_LENGTH + 4 :]

        # Try skipped key first
        mk = self._try_skipped_message_key(remote_dh_pub, msg_num)
        if mk is None:
            # Check if this is from a new remote key (DH ratchet step needed)
            if remote_dh_pub != self.dh_remote_public:
                # Discard old receiving chain and skipped keys (forward secrecy)
                self.receiving_chain = None
                self.skipped_keys.clear()
                # Perform DH ratchet: receive step + send step
                self.dh_remote_public = remote_dh_pub
                self._dh_ratchet_step()

            # Skip ahead to the needed message number in the new receiving chain
            if self.receiving_chain is not None:
                self._skip_message_keys(msg_num)
                result = self.receiving_chain.next_message_key()
                if result is None:
                    raise RuntimeError("Receiving chain exhausted")
                mk, next_ck = result
                self.receiving_chain = next_ck
            else:
                raise RuntimeError("No receiving chain")

        # Build header for AD verification
        header = remote_dh_pub + struct.pack("<I", msg_num & 0xFFFFFFFF)
        full_ad = associated_data + header

        # chacha20_poly1305_encrypt returns nonce(12) || ciphertext || tag(16)
        # Pass the entire encrypted_part to decrypt which extracts the nonce
        plaintext = chacha20_poly1305_decrypt(mk, encrypted_part, full_ad)

        self.messages_received += 1
        self.last_activity = time.time()
        return plaintext

    # ── Message Number / Counter ────────────────────────────────────────

    @property
    def current_message_number(self) -> int:
        return self.messages_sent + self.messages_received
