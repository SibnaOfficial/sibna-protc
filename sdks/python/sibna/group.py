"""
Sibna Protocol v3.0.1 — Group Messaging (Sender Keys).

Implements the sender-key group design from the Rust core
(`core/src/group/mod.rs`). Each group member has a SenderKey chain; messages are
encrypted with a per-message key derived from the chain and authenticated with
the sender's Ed25519 identity key.

Wire format for a group message:

    group_id(32) || sender_key_id(4 LE) || message_number(4 LE)
    || epoch(8 LE) || timestamp(8 LE) || ct_len(4 LE) || ciphertext
    || sig_len(4 LE) || signature

The ciphertext is ``nonce(12) || ct || tag`` from ChaCha20-Poly1305 with
associated data = group_id. The signature (Ed25519) covers
``signable_bytes() = group_id || sender_key_id || message_number || epoch ||
timestamp || SHA-256(ciphertext)``.

Key distribution (SenderKeyMessage) binds: group_id, sender public key,
encrypted sender key, key_id, timestamp, and an Ed25519 signature over
``group_id || key_id(4 LE) || encrypted_key || timestamp(8 LE)``.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import constants as C
from .crypto import (
    X25519KeyPair,
    Ed25519KeyPair,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    hkdf,
    sha256,
)
from .errors import CryptoError, ValidationError

MAX_GROUP_SIZE = C.MAX_GROUP_SIZE
MAX_GROUP_MESSAGE_SIZE = C.MAX_GROUP_MESSAGE_SIZE
DEFAULT_KEY_EXPIRATION_SECS = 7 * 86400

GROUP_MESSAGE_KEY_INFO = C.GROUP_MESSAGE_KEY_INFO
GROUP_CHAIN_KEY_INFO = C.GROUP_CHAIN_KEY_INFO
GROUP_KEY_DISTRIBUTE_INFO = C.GROUP_KEY_DISTRIBUTE_INFO


class SenderKey:
    """Sender key for group encryption (matches Rust ``SenderKey``)."""

    def __init__(
        self,
        chain_key: bytes,
        message_number: int = 0,
        key_id: int = 0,
        created_at: Optional[float] = None,
        expiration: Optional[float] = None,
    ):
        if len(chain_key) != C.KEY_LENGTH:
            raise ValidationError("chain_key must be 32 bytes")
        self.chain_key = chain_key
        self.message_number = message_number
        self.key_id = key_id
        self.created_at = created_at or time.time()
        self.expiration = expiration

    @classmethod
    def generate(cls, key_id: int = 0) -> "SenderKey":
        return cls(
            chain_key=os.urandom(C.KEY_LENGTH),
            key_id=key_id,
            expiration=time.time() + DEFAULT_KEY_EXPIRATION_SECS,
        )

    def next_message_key(self) -> bytes:
        """Derive next message key and advance the chain."""
        if self.expiration and time.time() > self.expiration:
            raise CryptoError("Sender key expired")
        message_key = hkdf(
            self.chain_key, salt=None, info=GROUP_MESSAGE_KEY_INFO, length=C.KEY_LENGTH
        )
        next_chain = hkdf(self.chain_key, salt=None, info=GROUP_CHAIN_KEY_INFO, length=C.KEY_LENGTH)
        self.chain_key = next_chain
        self.message_number += 1
        return message_key

    @property
    def is_expired(self) -> bool:
        if self.expiration is None:
            return False
        return time.time() > self.expiration

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_key": self.chain_key.hex(),
            "message_number": self.message_number,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "expiration": self.expiration,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SenderKey":
        return cls(
            chain_key=bytes.fromhex(d["chain_key"]),
            message_number=d["message_number"],
            key_id=d["key_id"],
            created_at=d.get("created_at"),
            expiration=d.get("expiration"),
        )


@dataclass
class SenderKeyMessage:
    """Key distribution message for group join."""

    group_id: bytes
    sender_public_key: bytes  # Ed25519 public key (32 bytes)
    encrypted_key: bytes  # ChaCha20-Poly1305(nonce||ct||tag) of sender chain key
    signature: bytes  # Ed25519 signature
    key_id: int
    timestamp: float = field(default_factory=time.time)

    def signable_bytes(self) -> bytes:
        return (
            self.group_id
            + struct.pack("<I", self.key_id)
            + self.encrypted_key
            + struct.pack("<q", int(self.timestamp))
        )

    def sign(self, identity: Ed25519KeyPair) -> bytes:
        self.signature = identity.sign(self.signable_bytes())
        return self.signature

    def verify_signature(self) -> bool:
        if len(self.signature) != C.ED25519_SIGNATURE_LENGTH:
            return False
        return Ed25519KeyPair.verify_with_key(
            self.sender_public_key, self.signable_bytes(), self.signature
        )

    def to_bytes(self) -> bytes:
        return (
            self.group_id
            + self.sender_public_key
            + struct.pack("<I", self.key_id)
            + struct.pack("<q", int(self.timestamp))
            + struct.pack("<I", len(self.encrypted_key))
            + self.encrypted_key
            + struct.pack("<I", len(self.signature))
            + self.signature
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SenderKeyMessage":
        offset = 0
        group_id = data[offset : offset + 32]
        offset += 32
        sender_public_key = data[offset : offset + 32]
        offset += 32
        key_id = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        timestamp = struct.unpack("<q", data[offset : offset + 8])[0]
        offset += 8
        enc_key_len = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        encrypted_key = data[offset : offset + enc_key_len]
        offset += enc_key_len
        sig_len = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        signature = data[offset : offset + sig_len]
        return cls(
            group_id=group_id,
            sender_public_key=sender_public_key,
            encrypted_key=encrypted_key,
            signature=signature,
            key_id=key_id,
            timestamp=float(timestamp),
        )


class GroupMessage:
    """An encrypted + signed group message."""

    def __init__(
        self,
        group_id: bytes,
        sender_key_id: int,
        message_number: int,
        ciphertext: bytes,
        epoch: int,
        timestamp: int,
        sender_signature: bytes,
    ):
        self.group_id = group_id
        self.sender_key_id = sender_key_id
        self.message_number = message_number
        self.ciphertext = ciphertext
        self.epoch = epoch
        self.timestamp = timestamp
        self.sender_signature = sender_signature

    def signable_bytes(self) -> bytes:
        ct_hash = sha256(self.ciphertext)
        buf = bytearray()
        buf.extend(self.group_id)
        buf.extend(struct.pack("<I", self.sender_key_id))
        buf.extend(struct.pack("<I", self.message_number))
        buf.extend(struct.pack("<Q", self.epoch))
        buf.extend(struct.pack("<Q", self.timestamp))
        buf.extend(ct_hash)
        return bytes(buf)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.extend(self.group_id)
        out.extend(struct.pack("<I", self.sender_key_id))
        out.extend(struct.pack("<I", self.message_number))
        out.extend(struct.pack("<Q", self.epoch))
        out.extend(struct.pack("<Q", self.timestamp))
        out.extend(struct.pack("<I", len(self.ciphertext)))
        out.extend(self.ciphertext)
        out.extend(struct.pack("<I", len(self.sender_signature)))
        out.extend(self.sender_signature)
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> "GroupMessage":
        offset = 0
        group_id = data[offset : offset + 32]
        offset += 32
        sender_key_id = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        message_number = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        epoch = struct.unpack("<Q", data[offset : offset + 8])[0]
        offset += 8
        timestamp = struct.unpack("<Q", data[offset : offset + 8])[0]
        offset += 8
        ct_len = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        ciphertext = data[offset : offset + ct_len]
        offset += ct_len
        sig_len = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        signature = data[offset : offset + sig_len]
        return cls(
            group_id=group_id,
            sender_key_id=sender_key_id,
            message_number=message_number,
            ciphertext=ciphertext,
            epoch=epoch,
            timestamp=timestamp,
            sender_signature=signature,
        )


class GroupSession:
    """Group encryption session using Sender Keys."""

    def __init__(self, group_id: bytes):
        if len(group_id) != 32:
            raise ValidationError("group_id must be 32 bytes")
        self.group_id = group_id
        self._sender_key: Optional[SenderKey] = None
        self._sender_keys: Dict[bytes, SenderKey] = {}  # public_key -> SenderKey
        self.members: List[bytes] = []
        self.epoch = 0
        self.created_at = time.time()
        self.last_activity = time.time()

    @classmethod
    def create(cls, group_id: Optional[bytes] = None) -> "GroupSession":
        if group_id is None:
            group_id = os.urandom(32)
        session = cls(group_id)
        session._sender_key = SenderKey.generate(key_id=1)
        return session

    def initialize_sender_key(self, key_id: int = 1) -> None:
        self._sender_key = SenderKey.generate(key_id=key_id)

    def add_member(self, public_key: bytes) -> None:
        if len(public_key) != 32:
            raise ValidationError("public key must be 32 bytes")
        if len(self.members) >= MAX_GROUP_SIZE:
            raise CryptoError("Group size limit reached")
        if public_key in self.members:
            raise CryptoError("Duplicate member")
        self.members.append(public_key)
        self.epoch += 1
        self.last_activity = time.time()

    def remove_member(self, public_key: bytes) -> None:
        self.members = [k for k in self.members if k != public_key]
        self._sender_keys.pop(public_key, None)
        self.epoch += 1
        # Immediate rotation for future secrecy.
        if self._sender_key is not None:
            self._sender_key = SenderKey.generate(key_id=self._sender_key.key_id + 1)
        self.last_activity = time.time()

    # ── Sender operations ───────────────────────────────────────────

    def encrypt(
        self, plaintext: bytes, signing_identity: Optional[Ed25519KeyPair] = None
    ) -> GroupMessage:
        if len(plaintext) > MAX_GROUP_MESSAGE_SIZE:
            raise CryptoError("Group message too large")
        if self._sender_key is None:
            raise CryptoError("No sender key — initialize group first")

        message_key = self._sender_key.next_message_key()
        nonce = os.urandom(C.NONCE_LENGTH)
        ct_and_tag = chacha20_poly1305_encrypt(message_key, plaintext, self.group_id, nonce)
        self._sender_key.message_number  # already advanced
        msg_number = self._sender_key.message_number - 1

        message = GroupMessage(
            group_id=self.group_id,
            sender_key_id=self._sender_key.key_id,
            message_number=msg_number,
            ciphertext=ct_and_tag,
            epoch=self.epoch,
            timestamp=int(time.time()),
            sender_signature=b"",
        )
        if signing_identity is not None:
            sig = signing_identity.sign(message.signable_bytes())
            message.sender_signature = sig

        self.last_activity = time.time()
        return message

    def get_key_distribution_message(
        self, identity: Ed25519KeyPair, member_public_keys: List[bytes]
    ) -> List[SenderKeyMessage]:
        if self._sender_key is None:
            raise CryptoError("No sender key")
        messages = []
        for member_pub in member_public_keys:
            ephemeral = X25519KeyPair.generate()
            shared = ephemeral.dh(member_pub)
            enc_key = hkdf(shared, salt=None, info=GROUP_KEY_DISTRIBUTE_INFO, length=C.KEY_LENGTH)
            encrypted = chacha20_poly1305_encrypt(
                enc_key, self._sender_key.chain_key
            )  # nonce||ct||tag
            msg = SenderKeyMessage(
                group_id=self.group_id,
                sender_public_key=identity.public_key,
                encrypted_key=encrypted,
                signature=b"",
                key_id=self._sender_key.key_id,
            )
            msg.sign(identity)
            messages.append(msg)
        return messages

    # ── Receiver operations ─────────────────────────────────────────

    def process_key_distribution(
        self, msg: SenderKeyMessage, our_x25519: X25519KeyPair, ephemeral_public: bytes
    ) -> None:
        if not msg.verify_signature():
            raise CryptoError("Invalid signature on key distribution message")
        shared = our_x25519.dh(ephemeral_public)
        enc_key = hkdf(shared, salt=None, info=GROUP_KEY_DISTRIBUTE_INFO, length=C.KEY_LENGTH)
        chain_key = chacha20_poly1305_decrypt(enc_key, msg.encrypted_key)
        # Epoch rollback protection: reject key_id <= existing.
        existing = self._sender_keys.get(msg.sender_public_key)
        if existing is not None and msg.key_id <= existing.key_id:
            raise CryptoError("Possible epoch rollback attack: key_id not newer")
        self._sender_keys[msg.sender_public_key] = SenderKey(
            chain_key=chain_key,
            key_id=msg.key_id,
        )

    def decrypt(self, message: GroupMessage, sender_public_key: bytes) -> bytes:
        if len(message.sender_signature) == 0:
            raise CryptoError("Unsigned group message rejected")
        # Verify sender signature before deriving keys.
        vk_ok = Ed25519KeyPair.verify_with_key(
            sender_public_key, message.signable_bytes(), message.sender_signature
        )
        if not vk_ok:
            raise CryptoError("Invalid group message signature")
        if message.group_id != self.group_id:
            raise CryptoError("Group ID mismatch")
        if message.epoch < self.epoch:
            raise CryptoError("Stale epoch (replay/rollback)")

        sender_key = self._sender_keys.get(sender_public_key)
        if sender_key is None:
            raise CryptoError("No sender key for this sender")
        if sender_key.key_id != message.sender_key_id:
            raise CryptoError("Key ID mismatch")

        # Skip ahead to target message number.
        while sender_key.message_number < message.message_number:
            sender_key.next_message_key()
        message_key = sender_key.next_message_key()

        plaintext = chacha20_poly1305_decrypt(message_key, message.ciphertext, self.group_id)
        self.last_activity = time.time()
        return plaintext


__all__ = [
    "SenderKey",
    "SenderKeyMessage",
    "GroupMessage",
    "GroupSession",
    "MAX_GROUP_SIZE",
    "MAX_GROUP_MESSAGE_SIZE",
]
