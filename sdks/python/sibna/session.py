"""
Sibna Protocol v3.0.1 — Session management.

High-level session combining X3DH handshake with Double Ratchet encryption.
Wire-compatible with the Rust core `DoubleRatchetSession`.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from . import constants as C
from .crypto import X25519KeyPair, Ed25519KeyPair, random_bytes
from .errors import CryptoError, SessionNotFoundError
from .ratchet import ChainKey, DoubleRatchet, HEADER_SIZE
from .x3dh import (
    PreKeyBundle,
    X3DHResult,
    generate_peer_bundle,
    x3dh_initiator,
    x3dh_responder,
)


@dataclass
class SessionConfig:
    """Session configuration."""

    max_skipped_messages: int = C.MAX_SKIPPED_MESSAGES
    max_chain_messages: int = C.MAX_CHAIN_MESSAGES


class Session:
    """
    Encrypted session combining X3DH + Double Ratchet.

    Usage:

        # Initiator
        session = Session()
        session.initiate_as_initiator(identity_x25519, ephemeral, peer_bundle)
        ct = session.encrypt(b"Hello!")

        # Responder
        session = Session()
        session.initiate_as_responder(identity, spk, opk, peer_identity, peer_ephemeral)
        pt = session.decrypt(ct)
    """

    def __init__(self, config: Optional[SessionConfig] = None):
        self.config = config or SessionConfig()
        self._ratchet: Optional[DoubleRatchet] = None
        self._session_id = str(uuid.uuid4())
        self._established_at: Optional[float] = None
        self._peer_id: Optional[bytes] = None
        self._role_is_initiator: Optional[bool] = None

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

    # ── Initiator ──────────────────────────────────────────────────────

    def initiate_as_initiator(
        self,
        identity: X25519KeyPair,
        ephemeral: X25519KeyPair,
        peer_bundle: PreKeyBundle,
        our_device_id: bytes = bytes(16),
        peer_device_id: bytes = bytes(16),
        use_pq: bool = False,
    ) -> bytes:
        """Perform X3DH as initiator and initialize the Double Ratchet.

        Returns the ephemeral public key (to send to the responder).
        """
        result = x3dh_initiator(
            identity_keypair=identity,
            ephemeral_keypair=ephemeral,
            peer_bundle=peer_bundle,
            our_device_id=our_device_id,
            peer_device_id=peer_device_id,
            use_pq=use_pq,
        )

        self._ratchet = DoubleRatchet.from_shared_secret(
            shared_secret=result.shared_secret,
            local_dh_private=ephemeral.private_key_bytes,
            remote_dh_public=peer_bundle.signed_prekey,
            role_is_initiator=True,
        )
        self._established_at = time.time()
        self._peer_id = peer_bundle.identity_key
        self._role_is_initiator = True
        return ephemeral.public_key

    # ── Responder ──────────────────────────────────────────────────────

    def initiate_as_responder(
        self,
        identity: X25519KeyPair,
        signed_prekey: X25519KeyPair,
        onetime_prekey: Optional[X25519KeyPair],
        peer_identity: bytes,
        peer_ephemeral: bytes,
        our_device_id: bytes = bytes(16),
        peer_device_id: bytes = bytes(16),
        our_pq_secret_key: Optional[bytes] = None,
        peer_pq_ciphertext: Optional[bytes] = None,
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
            our_pq_secret_key=our_pq_secret_key,
            peer_pq_ciphertext=peer_pq_ciphertext,
        )

        self._ratchet = DoubleRatchet.from_shared_secret(
            shared_secret=result.shared_secret,
            local_dh_private=signed_prekey.private_key_bytes,
            remote_dh_public=peer_ephemeral,
            role_is_initiator=False,
        )
        self._established_at = time.time()
        self._peer_id = peer_identity
        self._role_is_initiator = False

    # ── Restore from known shared secret (testing) ─────────────────────

    @classmethod
    def from_shared_secret(
        cls,
        shared_secret: bytes,
        local_dh_private: bytes,
        remote_dh_public: bytes,
        role_is_initiator: bool,
    ) -> "Session":
        s = cls()
        s._ratchet = DoubleRatchet.from_shared_secret(
            shared_secret=shared_secret,
            local_dh_private=local_dh_private,
            remote_dh_public=remote_dh_public,
            role_is_initiator=role_is_initiator,
        )
        s._established_at = time.time()
        return s

    # ── Encrypt / Decrypt ──────────────────────────────────────────────

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """Encrypt a message."""
        if self._ratchet is None:
            raise CryptoError("Session not established")
        return self._ratchet.ratchet_encrypt(plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt a message."""
        if self._ratchet is None:
            raise CryptoError("Session not established")
        return self._ratchet.ratchet_decrypt(ciphertext, associated_data)

    # ── Serialization ──────────────────────────────────────────────────

    def export_state(self) -> dict[str, Any]:
        """Export session state for persistence (does NOT include DH private scalar)."""
        if self._ratchet is None:
            return {}
        r = self._ratchet
        return {
            "session_id": self._session_id,
            "root_key": r.root_key.hex(),
            "dh_local_public": r.dh_local_public.hex() if r.dh_local_public else None,
            "dh_remote_public": r.dh_remote_public.hex() if r.dh_remote_public else None,
            "sending_chain_key": r.sending_chain.key.hex() if r.sending_chain else None,
            "sending_chain_index": r.sending_chain.index if r.sending_chain else 0,
            "receiving_chain_key": r.receiving_chain.key.hex() if r.receiving_chain else None,
            "receiving_chain_index": r.receiving_chain.index if r.receiving_chain else 0,
            "previous_counter": r.previous_counter,
            "messages_sent": r.messages_sent,
            "messages_received": r.messages_received,
            "role_is_initiator": self._role_is_initiator,
        }

    @classmethod
    def import_state(cls, state: dict[str, Any], config: Optional[SessionConfig] = None) -> "Session":
        """Restore a session from a previously exported state dict.

        The DH private scalar is deliberately NOT restored: it is regenerated
        on the next ratchet step, matching the Rust core behavior where
        ``dh_local_serde`` always serializes ``None``. This means exported
        state never exposes private key material.
        """
        s = cls(config=config)
        s._ratchet = cls._ratchet_from_dict(state)
        s._session_id = state.get("session_id", str(uuid.uuid4()))
        s._established_at = time.time()
        s._peer_id = None
        s._role_is_initiator = state.get("role_is_initiator")
        return s

    @staticmethod
    def _ratchet_from_dict(state: dict[str, Any]) -> DoubleRatchet:
        sending_chain = None
        if state.get("sending_chain_key"):
            sending_chain = ChainKey(
                key=bytes.fromhex(state["sending_chain_key"]),
                index=state.get("sending_chain_index", 0),
                max_messages=C.MAX_CHAIN_MESSAGES,
            )
        receiving_chain = None
        if state.get("receiving_chain_key"):
            receiving_chain = ChainKey(
                key=bytes.fromhex(state["receiving_chain_key"]),
                index=state.get("receiving_chain_index", 0),
                max_messages=C.MAX_CHAIN_MESSAGES,
            )
        return DoubleRatchet(
            root_key=bytes.fromhex(state["root_key"]),
            sending_chain=sending_chain,
            receiving_chain=receiving_chain,
            dh_local_private=None,  # Never restore private scalar
            dh_local_public=bytes.fromhex(state["dh_local_public"]) if state.get("dh_local_public") else None,
            dh_remote_public=bytes.fromhex(state["dh_remote_public"]) if state.get("dh_remote_public") else None,
            previous_counter=state.get("previous_counter", 0),
        )

    def __repr__(self) -> str:
        peer_hex = self._peer_id[:16].hex() if self._peer_id else "None"
        return (
            f"Session(id={self._session_id[:8]}..., "
            f"peer={peer_hex}..., "
            f"sent={self.messages_sent}, recv={self.messages_received}, "
            f"established={self.is_established})"
        )


__all__ = [
    "Session",
    "SessionConfig",
    "HEADER_SIZE",
]
