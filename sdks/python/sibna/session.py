"""
Sibna Protocol v3.0.1 — Session Management

High-level session that combines X3DH handshake with Double Ratchet
encryption. Matches the Rust core's DoubleRatchetSession API.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from .crypto import (
    KEY_LENGTH,
    X25519KeyPair,
    Ed25519KeyPair,
    random_bytes,
)
from .ratchet import DoubleRatchet, MAX_SKIPPED_MESSAGES
from .x3dh import (
    PreKeyBundle,
    X3DHResult,
    x3dh_initiator,
    x3dh_responder,
)


@dataclass
class SessionConfig:
    """Session configuration."""

    max_skipped_messages: int = MAX_SKIPPED_MESSAGES
    max_chain_messages: int = 4000


class Session:
    """
    Encrypted session combining X3DH + Double Ratchet.

    Usage:
        # Initiator
        session = Session()
        session.initiate_as_initiator(identity, ephemeral, peer_bundle)
        ciphertext = session.encrypt(b"Hello!")

        # Responder
        session = Session()
        session.initiate_as_responder(identity, spk, opk, peer_identity, peer_ephemeral)
        plaintext = session.decrypt(ciphertext)
    """

    def __init__(self, config: Optional[SessionConfig] = None):
        self.config = config or SessionConfig()
        self._ratchet: Optional[DoubleRatchet] = None
        self._session_id = str(uuid.uuid4())
        self._established_at: Optional[float] = None
        self._peer_id: Optional[bytes] = None

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def is_established(self) -> bool:
        return self._ratchet is not None

    @property
    def established_at(self) -> Optional[float]:
        return self._established_at

    @property
    def peer_id(self) -> Optional[bytes]:
        return self._peer_id

    @property
    def messages_sent(self) -> int:
        return self._ratchet.messages_sent if self._ratchet else 0

    @property
    def messages_received(self) -> int:
        return self._ratchet.messages_received if self._ratchet else 0

    # ── Initiator (who creates the session first) ───────────────────────

    def initiate_as_initiator(
        self,
        identity: X25519KeyPair,
        ephemeral: X25519KeyPair,
        peer_bundle: PreKeyBundle,
        our_device_id: bytes = bytes(16),
        peer_device_id: bytes = bytes(16),
    ) -> bytes:
        """
        Perform X3DH as initiator and initialize the Double Ratchet.
        Returns the ephemeral public key (sent to responder).
        """
        result = x3dh_initiator(
            identity_keypair=identity,
            ephemeral_keypair=ephemeral,
            peer_bundle=peer_bundle,
            our_device_id=our_device_id,
            peer_device_id=peer_device_id,
        )

        self._ratchet = DoubleRatchet.from_shared_secret(
            shared_secret=result.shared_secret,
            local_dh_private=ephemeral.private_key_bytes,
            remote_dh_public=peer_bundle.signed_prekey,
            role_is_initiator=True,
        )
        self._established_at = time.time()
        self._peer_id = peer_bundle.identity_key

        return ephemeral.public_key

    # ── Responder (who receives the first message) ──────────────────────

    def initiate_as_responder(
        self,
        identity: X25519KeyPair,
        signed_prekey: X25519KeyPair,
        onetime_prekey: Optional[X25519KeyPair],
        peer_identity: bytes,
        peer_ephemeral: bytes,
        our_device_id: bytes = bytes(16),
        peer_device_id: bytes = bytes(16),
    ) -> None:
        """Perform X3DH as responder and initialize the Double Ratchet."""
        result = x3dh_responder(
            identity_keypair=identity,
            signed_prekeypair=signed_prekey,
            onetime_prekeypair=onetime_prekey,
            peer_identity=peer_identity,
            peer_ephemeral=peer_ephemeral,
            our_device_id=our_device_id,
            peer_device_id=peer_device_id,
        )

        self._ratchet = DoubleRatchet.from_shared_secret(
            shared_secret=result.shared_secret,
            local_dh_private=signed_prekey.private_key_bytes,
            remote_dh_public=peer_ephemeral,
            role_is_initiator=False,
        )
        self._established_at = time.time()
        self._peer_id = peer_identity

    # ── Restore from known shared secret (testing) ──────────────────────

    @classmethod
    def from_shared_secret(
        cls,
        shared_secret: bytes,
        local_dh_private: bytes,
        remote_dh_public: bytes,
        role_is_initiator: bool,
    ) -> "Session":
        """Restore a session from a known shared secret (for testing)."""
        s = cls()
        s._ratchet = DoubleRatchet.from_shared_secret(
            shared_secret=shared_secret,
            local_dh_private=local_dh_private,
            remote_dh_public=remote_dh_public,
            role_is_initiator=role_is_initiator,
        )
        s._established_at = time.time()
        return s

    # ── Encrypt / Decrypt ───────────────────────────────────────────────

    def encrypt(
        self, plaintext: bytes, associated_data: bytes = b""
    ) -> bytes:
        """Encrypt a message."""
        if self._ratchet is None:
            raise RuntimeError("Session not established")
        return self._ratchet.ratchet_encrypt(plaintext, associated_data)

    def decrypt(
        self, ciphertext: bytes, associated_data: bytes = b""
    ) -> bytes:
        """Decrypt a message."""
        if self._ratchet is None:
            raise RuntimeError("Session not established")
        return self._ratchet.ratchet_decrypt(ciphertext, associated_data)

    # ── Serialization ───────────────────────────────────────────────────

    def export_state(self) -> dict:
        """Export session state for persistence."""
        if self._ratchet is None:
            return {}
        r = self._ratchet
        return {
            "session_id": self._session_id,
            "root_key": r.root_key.hex(),
            "dh_local_private": r.dh_local_private.hex() if r.dh_local_private else None,
            "dh_local_public": r.dh_local_public.hex() if r.dh_local_public else None,
            "dh_remote_public": r.dh_remote_public.hex() if r.dh_remote_public else None,
            "sending_chain_key": r.sending_chain.key.hex() if r.sending_chain else None,
            "sending_chain_index": r.sending_chain.index if r.sending_chain else 0,
            "receiving_chain_key": r.receiving_chain.key.hex() if r.receiving_chain else None,
            "receiving_chain_index": r.receiving_chain.index if r.receiving_chain else 0,
            "messages_sent": r.messages_sent,
            "messages_received": r.messages_received,
            "previous_counter": r.previous_counter,
        }

    def __repr__(self) -> str:
        peer_hex = self._peer_id[:16].hex() if self._peer_id else "None"
        return (
            f"Session(id={self._session_id[:8]}..., "
            f"peer={peer_hex}..., "
            f"sent={self.messages_sent}, recv={self.messages_received}, "
            f"established={self.is_established})"
        )
