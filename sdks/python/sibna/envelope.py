"""
Sibna Protocol v3.0.2 — Signed envelope (relay transport).

Canonical signed payload matches the Rust relay server
(`server/src/ws.rs::route_message`):

    canonical = u64_be(len(recipient_id)) || recipient_id_bytes
             || u64_be(len(message_id))   || message_id_bytes
             || u64_be(len(payload_hex))  || payload_hex_bytes
             || u64_be(len(sender_id))    || sender_id_bytes

Length-prefix encoding prevents field-boundary reinterpretation attacks.

The envelope is signed by the sender's Ed25519 identity key over the canonical
payload directly. The relay verifies this signature before routing.

Signed fields (authenticated): recipient_id, message_id, payload_hex, sender_id.
The signature binds these four fields together so an attacker cannot swap or
reinterpret field boundaries.

Fields intentionally NOT covered by the signature:

- `timestamp`: delivery/receipt timestamp. It is NOT authenticated and is
  re-stamped by the server on receipt (`route_message` overwrites the
  client-supplied value). It is a transport hint only. Message expiration is
  enforced server-side by the offline-queue TTL (7 days), and replay is
  prevented by server message_id deduplication plus client ratchet
  sequence-number tracking — NOT by rejecting envelopes on wall-clock age.
  Rejecting old envelopes here would break legitimate store-and-forward /
  delayed delivery (offline recipients, reconnect replay).

- `compressed`: transport hint (LZ4). Flipping it causes a decompression or
  AEAD-decryption failure (message dropped), not a confidentiality or
  integrity breach. It is authenticated indirectly: a mismatched flag makes
  the sealed payload fail to decrypt.

- `receiver_id`: not part of the envelope (the relay routes by recipient_id
  from the URL/query, not from the envelope content).

See PROTOCOL_SPECIFICATION.md §4 for the canonical form.
"""

from __future__ import annotations

import struct
import uuid
from typing import Any, Dict, Protocol

from .crypto import Ed25519KeyPair
from .errors import CryptoError


class Signer(Protocol):
    """Anything that can sign with an Ed25519 identity and expose its public key."""

    @property
    def public_key(self) -> bytes: ...

    def sign(self, data: bytes) -> bytes: ...


# ENVELOPE_MAX_AGE_SECS is retained for API compatibility but is no longer
# enforced by verify_signed_envelope. Expiration is server-side (queue TTL)
# and replay protection is message-ID / sequence-number based, so a
# legitimately delayed envelope (offline queue up to 7 days) must not be
# rejected merely because its creation timestamp is old.
ENVELOPE_MAX_AGE_SECS = 300


def _canonical_payload(
    recipient_id: str, message_id: str, payload_hex: str, sender_id: str
) -> bytes:
    """Build the length-prefixed canonical signed payload (4 fields).

    Matches Rust canonical form (server/src/main.rs::send_message_handler and
    server/src/ws.rs::route_message):
        u64_be(len(recipient_id)) || recipient_id_bytes
        || u64_be(len(message_id))   || message_id_bytes
        || u64_be(len(payload_hex))  || payload_hex_bytes
        || u64_be(len(sender_id))    || sender_id_bytes
    Length-prefix encoding prevents field-boundary reinterpretation attacks.
    The four-field canonical (recipient_id, message_id, payload_hex, sender_id)
    is signed by the sender's Ed25519 identity key.
    """
    r = recipient_id.encode()
    m = message_id.encode()
    p = payload_hex.encode()
    s = sender_id.encode()
    out = bytearray()
    out.extend(struct.pack(">Q", len(r)))
    out.extend(r)
    out.extend(struct.pack(">Q", len(m)))
    out.extend(m)
    out.extend(struct.pack(">Q", len(p)))
    out.extend(p)
    out.extend(struct.pack(">Q", len(s)))
    out.extend(s)
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

    The signature covers the canonical payload directly (not SHA-512 of canonical).
    The canonical payload includes recipient_id, message_id, payload_hex, and sender_id.
    ``timestamp`` and ``compressed`` are transport metadata and are NOT part
    of the signed canonical payload (see module docstring).
    """
    if message_id is None:
        message_id = str(uuid.uuid4())
    if timestamp is None:
        import time

        timestamp = int(time.time())

    sender_id = identity.public_key.hex()
    canonical = _canonical_payload(recipient_id, message_id, payload_hex, sender_id)
    signature = identity.sign(canonical)

    return {
        "recipient_id": recipient_id,
        "payload_hex": payload_hex,
        "sender_id": sender_id,
        "timestamp": timestamp,
        "message_id": message_id,
        "signature_hex": signature.hex(),
        "compressed": compressed,
    }


def verify_signed_envelope(envelope: Dict[str, Any]) -> bool:
    """Verify a received envelope's Ed25519 signature.

    Returns True if the signature is valid, False otherwise. Always call
    before processing.

    The signature authenticates all four canonical fields: recipient_id,
    message_id, payload_hex, and sender_id. Age/freshness is deliberately
    NOT enforced here: delayed (offline-queued) envelopes may carry creation
    timestamps far in the past and must still be verifiable. Expiration is
    enforced server-side by the queue TTL, and replay is prevented by
    message-ID deduplication plus client ratchet sequence-number tracking.
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

        canonical = _canonical_payload(
            recipient_id, message_id, payload_hex, envelope["sender_id"]
        )
        # Signature is over the canonical payload directly (not SHA-512 of canonical)

        vk = Ed25519PublicKey.from_public_bytes(sender_id)
        vk.verify(signature, canonical)

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