"""
Sibna Protocol v3.0.1 — Group Messaging (Sender Keys)

Implements Sender Keys protocol for efficient group encryption.
Matches the Rust core's group module exactly:
  - Chain key derivation: HKDF(chain_key, "SibnaGroupMessageKey_v3") = message_key
  - Chain advance: HKDF(chain_key, "SibnaGroupChainKey_v3") = next_chain_key
  - Wire format: group_id(32) || key_id(4) || message_number(4) || nonce(12) || ciphertext+tag
  - Signature: Ed25519 over signable_bytes
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .crypto import (
    KEY_LENGTH,
    NONCE_LENGTH,
    Ed25519KeyPair,
    X25519KeyPair,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    hkdf,
    hmac_sha256,
    random_bytes,
    sha256,
)

MAX_GROUP_SIZE = 256
MAX_GROUP_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_KEY_EXPIRATION_SECS = 7 * 86400  # 7 days


# ── Sender Key ──────────────────────────────────────────────────────────────


class SenderKey:
    """
    Sender key for group encryption.
    Matches Rust SenderKey.
    """

    def __init__(
        self,
        chain_key: bytes,
        message_number: int = 0,
        key_id: int = 0,
        created_at: Optional[float] = None,
        expiration: Optional[float] = None,
    ):
        self.chain_key = chain_key
        self.message_number = message_number
        self.key_id = key_id
        self.created_at = created_at or time.time()
        self.expiration = expiration

    @classmethod
    def generate(cls, key_id: int = 0) -> "SenderKey":
        """Generate a new random sender key."""
        return cls(
            chain_key=random_bytes(KEY_LENGTH),
            key_id=key_id,
            expiration=time.time() + DEFAULT_KEY_EXPIRATION_SECS,
        )

    def next_message_key(self) -> Optional[bytes]:
        """
        Derive the next message key and advance the chain.
        Matches Rust SenderKey::next_message_key().
        """
        if self.expiration and time.time() > self.expiration:
            raise RuntimeError("Sender key expired")

        # message_key = HKDF(chain_key, info="SibnaGroupMessageKey_v3")
        message_key = hkdf(
            self.chain_key,
            salt=None,
            info=b"SibnaGroupMessageKey_v3",
            length=KEY_LENGTH,
        )

        # next_chain = HKDF(chain_key, info="SibnaGroupChainKey_v3")
        next_chain = hkdf(
            self.chain_key,
            salt=None,
            info=b"SibnaGroupChainKey_v3",
            length=KEY_LENGTH,
        )

        self.chain_key = next_chain
        self.message_number += 1

        return message_key

    @property
    def is_expired(self) -> bool:
        if self.expiration is None:
            return False
        return time.time() > self.expiration

    def age_secs(self) -> float:
        return time.time() - self.created_at

    def needs_rotation(self) -> bool:
        return self.is_expired or self.age_secs() > 86400

    def to_dict(self) -> dict:
        return {
            "chain_key": self.chain_key.hex(),
            "message_number": self.message_number,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "expiration": self.expiration,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SenderKey":
        return cls(
            chain_key=bytes.fromhex(d["chain_key"]),
            message_number=d["message_number"],
            key_id=d["key_id"],
            created_at=d.get("created_at"),
            expiration=d.get("expiration"),
        )


# ── Sender Key Distribution Message ─────────────────────────────────────────


@dataclass
class SenderKeyMessage:
    """
    Key distribution message for group join.
    Matches Rust SenderKeyMessage.
    """

    group_id: bytes  # 32 bytes
    sender_public_key: bytes  # Ed25519 public key (32 bytes)
    encrypted_key: bytes  # Encrypted sender key
    signature: bytes  # Ed25519 signature
    key_id: int
    timestamp: float = field(default_factory=time.time)

    def signable_bytes(self) -> bytes:
        """Bytes to sign: group_id || key_id || encrypted_key || timestamp."""
        return (
            self.group_id
            + struct.pack("<I", self.key_id)
            + self.encrypted_key
            + struct.pack("<q", int(self.timestamp))
        )

    def sign(self, identity: Ed25519KeyPair) -> bytes:
        """Sign this distribution message."""
        self.signature = identity.sign(self.signable_bytes())
        return self.signature

    def verify_signature(self) -> bool:
        """Verify the Ed25519 signature."""
        if len(self.signature) != 64:
            return False
        return Ed25519KeyPair.verify_with_key(
            self.sender_public_key,
            self.signable_bytes(),
            self.signature,
        )

    def to_bytes(self) -> bytes:
        """Serialize to bytes for wire transmission."""
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
        """Deserialize from bytes."""
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


# ── Group Session ───────────────────────────────────────────────────────────


class GroupSession:
    """
    Group encryption session using Sender Keys.

    Each member has their own SenderKey. When joining, the key is
    distributed via SenderKeyMessage encrypted to each member.
    """

    def __init__(self, group_id: bytes):
        if len(group_id) != 32:
            raise ValueError("group_id must be 32 bytes")
        self.group_id = group_id
        self._sender_key: Optional[SenderKey] = None
        self._sender_keys: Dict[bytes, SenderKey] = {}  # public_key -> SenderKey
        self._key_rotation_count = 0

    @classmethod
    def create(cls, group_id: Optional[bytes] = None) -> "GroupSession":
        """Create a new group session with a random group ID."""
        if group_id is None:
            group_id = random_bytes(32)
        session = cls(group_id)
        session._sender_key = SenderKey.generate(key_id=0)
        return session

    # ── Sender operations ───────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a group message using our sender key.
        Wire format: group_id(32) || key_id(4) || msg_number(4) || nonce(12) || ciphertext+tag
        """
        if self._sender_key is None:
            raise RuntimeError("No sender key — join or create group first")

        mk = self._sender_key.next_message_key()
        if mk is None:
            raise RuntimeError("Sender key chain exhausted")

        nonce = random_bytes(NONCE_LENGTH)
        msg_number = self._sender_key.message_number - 1

        # Build AD: group_id || key_id || message_number
        ad = (
            self.group_id
            + struct.pack("<I", self._sender_key.key_id)
            + struct.pack("<I", msg_number)
        )

        ciphertext = chacha20_poly1305_encrypt(mk, plaintext, ad, nonce)

        return (
            self.group_id
            + struct.pack("<I", self._sender_key.key_id)
            + struct.pack("<I", msg_number)
            + ciphertext
        )

    def get_key_distribution_message(
        self, identity: Ed25519KeyPair, member_public_keys: List[bytes]
    ) -> List[SenderKeyMessage]:
        """
        Create key distribution messages for group members.
        Each message encrypts our sender key to a member's X25519 key.
        """
        if self._sender_key is None:
            raise RuntimeError("No sender key")

        messages = []
        for member_pub in member_public_keys:
            # Encrypt sender key to member (using X25519 DH + HKDF + ChaCha20)
            ephemeral = X25519KeyPair.generate()
            shared = ephemeral.dh(member_pub)
            enc_key = hkdf(shared, info=b"SibnaGroupKeyDistribute_v3", length=KEY_LENGTH)
            encrypted = chacha20_poly1305_encrypt(
                enc_key, self._sender_key.chain_key
            )

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

    # ── Receiver operations ─────────────────────────────────────────────

    def process_key_distribution(
        self,
        msg: SenderKeyMessage,
        our_x25519: X25519KeyPair,
        ephemeral_public: bytes,
    ) -> None:
        """Process a key distribution message and store the sender's key."""
        if not msg.verify_signature():
            raise ValueError("Invalid signature on key distribution message")

        shared = our_x25519.dh(ephemeral_public)
        enc_key = hkdf(shared, info=b"SibnaGroupKeyDistribute_v3", length=KEY_LENGTH)
        chain_key = chacha20_poly1305_decrypt(enc_key, msg.encrypted_key)

        self._sender_keys[msg.sender_public_key] = SenderKey(
            chain_key=chain_key,
            key_id=msg.key_id,
        )

    def decrypt(
        self,
        ciphertext: bytes,
        sender_public_key: bytes,
    ) -> bytes:
        """
        Decrypt a group message from a specific sender.
        """
        if len(ciphertext) < 32 + 4 + 4 + NONCE_LENGTH + 16:
            raise ValueError("Ciphertext too short")

        offset = 0
        group_id = ciphertext[offset : offset + 32]
        offset += 32
        key_id = struct.unpack("<I", ciphertext[offset : offset + 4])[0]
        offset += 4
        msg_number = struct.unpack("<I", ciphertext[offset : offset + 4])[0]
        offset += 4
        encrypted_part = ciphertext[offset:]

        if group_id != self.group_id:
            raise ValueError("Group ID mismatch")

        sender_key = self._sender_keys.get(sender_public_key)
        if sender_key is None:
            raise RuntimeError("No sender key for this sender")

        if sender_key.key_id != key_id:
            raise ValueError(f"Key ID mismatch: expected {sender_key.key_id}, got {key_id}")

        # Skip ahead if needed
        while sender_key.message_number < msg_number:
            mk = sender_key.next_message_key()
            if mk is None:
                raise RuntimeError("Sender key chain exhausted")

        mk = sender_key.next_message_key()
        if mk is None:
            raise RuntimeError("Sender key chain exhausted")

        nonce = encrypted_part[:NONCE_LENGTH]
        actual_ct = encrypted_part[NONCE_LENGTH:]

        ad = (
            self.group_id
            + struct.pack("<I", key_id)
            + struct.pack("<I", msg_number)
        )

        return chacha20_poly1305_decrypt(mk, actual_ct, ad, nonce)

    # ── Key rotation ────────────────────────────────────────────────────

    def rotate_sender_key(self) -> SenderKey:
        """Rotate to a new sender key."""
        self._key_rotation_count += 1
        self._sender_key = SenderKey.generate(key_id=self._key_rotation_count)
        return self._sender_key

    @property
    def sender_key(self) -> Optional[SenderKey]:
        return self._sender_key

    def __repr__(self) -> str:
        return (
            f"GroupSession(group_id={self.group_id[:8].hex()}..., "
            f"members={len(self._sender_keys)}, "
            f"rotations={self._key_rotation_count})"
        )
