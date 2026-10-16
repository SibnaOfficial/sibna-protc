"""
Sibna Protocol v3.0.1 — Signed envelope (relay transport).

Canonical signed payload matches the Rust relay server
(`server/src/ws.rs::route_message`):

    canonical = u64_be(len(recipient_id)) || recipient_id_bytes
             || u64_be(len(message_id))   || message_id_bytes
             || u64_be(len(payload_hex))  || payload_hex_bytes

Length-prefix encoding prevents field-boundary reinterpretation attacks.

The envelope is signed by the sender's Ed25519 identity key over the SHA-512
of the canonical payload. The relay verifies this signature before routing.
"""

from __future__ import annotations

import hashlib
import struct
import time
import uuid
from typing import Any, Dict, Protocol

from .crypto import Ed25519KeyPair
from .errors import CryptoError


class Signer(Protocol):
    """Anything that can sign with an Ed25519 identity and expose its public key."""

    @property
    def public_key(self) -> bytes: ...

    def sign(self, data: bytes) -> bytes: ...


ENVELOPE_MAX_AGE_SECS = 300  # signed envelopes older than 5 minutes are rejected


def _canonical_payload(recipient_id: str, message_id: str, payload_hex: str) -> bytes:
    """Build the length-prefixed canonical signed payload."""
    r = recipient_id.encode()
    m = message_id.encode()
    p = payload_hex.encode()
    out = bytearray()
    out.extend(struct.pack(">Q", len(r)))
    out.extend(r)
    out.extend(struct.pack(">Q", len(m)))
    out.extend(m)
    out.extend(struct.pack(">Q", len(p)))
    out.extend(p)
    return bytes(out)


def make_signed_envelope(
    identity: Signer,
    recipient_id: str,
    payload_hex: str,
    message_id: str | None = None,
    timestamp: int | None = None,
    compressed: bool = False,
) -> Dict[str, Any]:
    """Create a signed, sealed envelope.

    The signature covers ``SHA-512(canonical)`` where canonical is the
    length-prefixed encoding of recipient_id, message_id, and payload_hex.
    """
    if message_id is None:
        message_id = str(uuid.uuid4())
    if timestamp is None:
        timestamp = int(time.time())

    canonical = _canonical_payload(recipient_id, message_id, payload_hex)
    signing_hash = hashlib.sha512(canonical).digest()
    signature = identity.sign(signing_hash)

    return {
        "recipient_id": recipient_id,
        "payload_hex": payload_hex,
        "sender_id": identity.public_key.hex(),
        "timestamp": timestamp,
        "message_id": message_id,
        "signature_hex": signature.hex(),
        "compressed": compressed,
    }


def verify_signed_envelope(envelope: Dict[str, Any]) -> bool:
    """Verify a received envelope's Ed25519 signature and freshness.

    Returns True if valid, False otherwise. Always call before processing.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.exceptions import InvalidSignature

        recipient_id = envelope["recipient_id"]
        message_id = envelope["message_id"]
        payload_hex = envelope["payload_hex"]
        sender_id = bytes.fromhex(envelope["sender_id"])
        signature = bytes.fromhex(envelope["signature_hex"])
        timestamp = envelope["timestamp"]

        canonical = _canonical_payload(recipient_id, message_id, payload_hex)
        signing_hash = hashlib.sha512(canonical).digest()

        vk = Ed25519PublicKey.from_public_bytes(sender_id)
        vk.verify(signature, signing_hash)

        # Freshness: reject envelopes older than 5 minutes or far in future.
        now = int(time.time())
        age = now - timestamp
        if age > ENVELOPE_MAX_AGE_SECS or age < -ENVELOPE_MAX_AGE_SECS:
            return False

        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    except Exception:
        return False


__all__ = [
    "make_signed_envelope",
    "verify_signed_envelope",
    "ENVELOPE_MAX_AGE_SECS",
]
