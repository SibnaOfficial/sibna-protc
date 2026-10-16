"""
Sibna Protocol v3.0.1 — P2P Transport and Handshake.

Implements the peer-to-peer transport and handshake described in
``PROTOCOL_SPECIFICATION.md`` section 6 and the retained Rust core
(``core/src/p2p/``).

The P2P handshake is a 4-message exchange over a length-prefixed TCP stream::

    Initiator                                          Responder
    ─────────────────                                  ───────────────
    1.  → P2pMsg::Hello  (version, ephemeral_pub, device_id)
                                              ───────────────────────────────►
    (← P2pMsg::Bundle)           2. Bob sends AEAD-encrypted StealthBundle
                                              ◄───────────────────────────────
    3.  → P2pMsg::Envelope  (AEAD-encrypted StealthEnvelope)
                                              ───────────────────────────────►
                                              4. Bob confirms
    (← P2pMsg::Ok)           ◄───────────────────────────────

Transport encryption
--------------------
Both sides generate a single ephemeral X25519 key that is used for *both* the
transport encryption and the X3DH handshake.  The transient transport key is::

    shared = X25519(our_ephemeral, peer_ephemeral_pub)
    key    = HKDF-SHA256(salt=b"SibnaHandshake_v4", ikm=shared)

This key protects the StealthBundle and StealthEnvelope payloads with
ChaCha20-Poly1305 (independent random nonces, associated data
``b"handshake_bundle"`` / ``b"handshake_envelope"`` / ``b"handshake_ok"``).

Transcript binding
------------------
The transcript hash is constructed identically to ``x3dh_initiator_v3`` /
``x3dh_responder_v3``::

    T_internal = BLAKE3(initiator_id || initiator_ephemeral ||
                        responder_id || responder_spk || [responder_opk] ||
                        initiator_device_id || responder_device_id)
    T = HKDF-Extract(salt=transcript_hash_ext, ikm=T_internal),
        expand(info="SibnaX3DH_TranscriptBind_v3")

This is then passed as the external transcript binding to the X3DH handshake,
cryptographically coupling the P2P transport ephemeral to the X3DH session.

Peer identity
-------------
``P2pConfig.expected_peer_identity`` holds the peer's Ed25519 identity key.
The handshake rejects any peer whose identity does not match (guarding against
MITM substitution of the prekey bundle).  Leave it ``None`` only for anonymous
discovery; verify safety numbers interactively after connection in that case.

NAT traversal / mDNS discovery
------------------------------
mDNS discovery, STUN and IGD (NAT traversal) are operating-system facilities
that are not available portably in pure Python.  They are therefore *not*
implemented in this SDK.  Set ``enable_mdns = False`` (the default); the
Python SDK connects to a known peer address directly.  This is documented as a
limitation rather than disguised as a complete implementation.
"""

from __future__ import annotations

import asyncio
import os
import struct
from dataclasses import dataclass
from typing import Any, Optional

from . import constants as C
from .crypto import (
    X25519KeyPair,
    Ed25519KeyPair,
    blake3_hash,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    hkdf,
)
from .errors import CryptoError, ValidationError

# ── Wire format ─────────────────────────────────────────────────────────────

# Each P2P message is framed as: u32 big-endian length + payload bytes.
HEADER_LEN = 4
MAX_FRAME_BYTES = 10 * 1024 * 1024

# Associated data for the three AEAD-encrypted handshake payloads, matching
# ``core/src/p2p/handshake.rs``.
HANDSHAKE_BUNDLE_AD = b"handshake_bundle"
HANDSHAKE_ENVELOPE_AD = b"handshake_envelope"
HANDSHAKE_OK_AD = b"handshake_ok"

# Handshake transcript key derivation (matches Rust derive_handshake_key).
HANDSHAKE_KDF_INFO = b"SibnaHandshake_v4"

P2P_PROTOCOL_VERSION = 4  # bumped on any breaking wire-format change


class P2pError(Exception):
    """Base exception for P2P transport/handshake errors."""


class NetworkError(P2pError):
    """Network or transport failure."""


class ProtocolError(P2pError):
    """Protocol-level handshake violation (e.g. identity mismatch)."""


# ── Wire messages ───────────────────────────────────────────────────────────


@dataclass
class Hello:
    """Step 1: Initiator → Responder. Announces ephemeral public key + device ID."""

    version: int
    ephemeral_pub: bytes  # 32 bytes
    initiator_device_id: bytes  # 16 bytes

    def encode(self) -> bytes:
        out = bytearray()
        out.append(self.version & 0xFF)
        out.extend(self.ephemeral_pub)
        out.extend(self.initiator_device_id)
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "Hello":
        if len(data) < 1 + 32 + 16:
            raise ProtocolError("Hello payload too short")
        version = data[0]
        ephemeral_pub = data[1 : 1 + 32]
        initiator_device_id = data[1 + 32 : 1 + 32 + 16]
        return cls(
            version=version, ephemeral_pub=ephemeral_pub, initiator_device_id=initiator_device_id
        )


@dataclass
class Bundle:
    """Step 2: Responder → Initiator. AEAD-encrypted StealthBundle."""

    ephemeral_pub: bytes  # 32 bytes
    encrypted_bundle: bytes

    def encode(self) -> bytes:
        out = bytearray()
        out.extend(self.ephemeral_pub)
        out.extend(struct.pack("<I", len(self.encrypted_bundle)))
        out.extend(self.encrypted_bundle)
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "Bundle":
        if len(data) < 32 + 4:
            raise ProtocolError("Bundle payload too short")
        ephemeral_pub = data[:32]
        length = struct.unpack("<I", data[32 : 32 + 4])[0]
        encrypted_bundle = data[32 + 4 : 32 + 4 + length]
        return cls(ephemeral_pub=ephemeral_pub, encrypted_bundle=encrypted_bundle)


@dataclass
class Envelope:
    """Step 3: Initiator → Responder. AEAD-encrypted StealthEnvelope."""

    encrypted_envelope: bytes

    def encode(self) -> bytes:
        out = bytearray()
        out.extend(struct.pack("<I", len(self.encrypted_envelope)))
        out.extend(self.encrypted_envelope)
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "Envelope":
        if len(data) < 4:
            raise ProtocolError("Envelope payload too short")
        length = struct.unpack("<I", data[:4])[0]
        encrypted_envelope = data[4 : 4 + length]
        return cls(encrypted_envelope=encrypted_envelope)


@dataclass
class Ok:
    """Step 4: Responder → Initiator. AEAD-encrypted confirmation."""

    encrypted_ok: bytes

    def encode(self) -> bytes:
        out = bytearray()
        out.extend(struct.pack("<I", len(self.encrypted_ok)))
        out.extend(self.encrypted_ok)
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "Ok":
        if len(data) < 4:
            raise ProtocolError("Ok payload too short")
        length = struct.unpack("<I", data[:4])[0]
        encrypted_ok = data[4 : 4 + length]
        return cls(encrypted_ok=encrypted_ok)


# ── Config ──────────────────────────────────────────────────────────────────


@dataclass
class P2pConfig:
    """Configuration for a P2P node.

    ``expected_peer_identity`` is the peer's Ed25519 public key (32 bytes).
    When set, the handshake rejects any peer whose identity does not match.
    Leave ``None`` only for anonymous discovery; verify safety numbers
    interactively after connection in that case.
    """

    bind_addr: str = "0.0.0.0:0"
    handshake_timeout_secs: int = 30
    max_message_size: int = 10 * 1024 * 1024
    expected_peer_identity: Optional[bytes] = None  # 32-byte Ed25519 key


# ── Handshake crypto ────────────────────────────────────────────────────────


def derive_handshake_key(our_ephemeral: X25519KeyPair, peer_ephemeral_pub: bytes) -> bytes:
    """Derive the transient transport encryption key.

    shared = X25519(our_ephemeral, peer_ephemeral_pub)
    key    = HKDF-SHA256(salt=b"SibnaHandshake_v4", ikm=shared)
    """
    shared = our_ephemeral.dh(peer_ephemeral_pub)
    return hkdf(shared, salt=None, info=HANDSHAKE_KDF_INFO, length=C.KEY_LENGTH)


def build_transcript(
    initiator_identity: bytes,
    initiator_ephemeral: bytes,
    responder_identity: bytes,
    responder_signed_prekey: bytes,
    responder_onetime_prekey: Optional[bytes],
    initiator_device_id: bytes,
    responder_device_id: bytes,
) -> bytes:
    """Build the X3DH-aligned transcript hash.

    Matches ``core/src/p2p/handshake.rs::build_transcript`` exactly so that the
    external transcript binding is consistent with the pure-X3DH flow.
    """
    parts = [
        initiator_identity,
        initiator_ephemeral,
        responder_identity,
        responder_signed_prekey,
    ]
    if responder_onetime_prekey is not None:
        parts.append(responder_onetime_prekey)
    parts.extend([initiator_device_id, responder_device_id])
    return blake3_hash(*parts)


# ── Transport helpers ───────────────────────────────────────────────────────


async def _read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one length-prefixed frame from the stream."""
    header = await reader.readexactly(HEADER_LEN)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise NetworkError(f"Invalid frame length: {length}")
    return await reader.readexactly(length)


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Write one length-prefixed frame to the stream."""
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()


async def _encrypt_send(
    writer: asyncio.StreamWriter,
    key: bytes,
    ad: bytes,
    plaintext: bytes,
) -> None:
    """Encrypt ``plaintext`` with ChaCha20-Poly1305 and send as one frame.

    ``chacha20_poly1305_encrypt`` already returns ``nonce + ct + tag``, so we
    send that directly.
    """
    nonce = os.urandom(C.NONCE_LENGTH)
    ct_and_tag = chacha20_poly1305_encrypt(key, plaintext, ad, nonce)
    await _write_frame(writer, ct_and_tag)


async def _decrypt_verify(
    reader: asyncio.StreamReader,
    key: bytes,
    ad: bytes,
) -> bytes:
    """Read, decrypt and authenticate one frame. Returns plaintext."""
    raw = await _read_frame(reader)
    return chacha20_poly1305_decrypt(key, raw, ad)


# ── StealthBundle / StealthEnvelope serialization ───────────────────────────

# These mirror ``core/src/p2p/handshake.rs`` structs (bincode-serialized in Rust,
# but here we use an explicit length-prefixed layout for clarity and portability).


def encode_stealth_bundle(
    responder_ed25519_pub: bytes,
    responder_x25519_pub: bytes,
    responder_device_id: bytes,
    responder_signed_prekey: bytes,
    responder_signed_prekey_signature: bytes,
    responder_onetime_prekey: Optional[bytes],
) -> bytes:
    out = bytearray()
    out.extend(responder_ed25519_pub)
    out.extend(responder_x25519_pub)
    out.extend(responder_device_id)
    out.extend(responder_signed_prekey)
    out.extend(responder_signed_prekey_signature)
    if responder_onetime_prekey is not None:
        out.extend(struct.pack("<I", len(responder_onetime_prekey)))
        out.extend(responder_onetime_prekey)
    else:
        out.extend(struct.pack("<I", 0))
    return bytes(out)


def decode_stealth_bundle(data: bytes) -> dict[str, Any]:
    offset = 0
    responder_ed25519_pub = data[offset : offset + 32]
    offset += 32
    responder_x25519_pub = data[offset : offset + 32]
    offset += 32
    responder_device_id = data[offset : offset + 16]
    offset += 16
    responder_signed_prekey = data[offset : offset + 32]
    offset += 32
    responder_signed_prekey_signature = data[offset : offset + 64]
    offset += 64
    opk_len = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4
    responder_onetime_prekey = data[offset : offset + opk_len]
    offset += opk_len
    return {
        "responder_ed25519_pub": responder_ed25519_pub,
        "responder_x25519_pub": responder_x25519_pub,
        "responder_device_id": responder_device_id,
        "responder_signed_prekey": responder_signed_prekey,
        "responder_signed_prekey_signature": responder_signed_prekey_signature,
        "responder_onetime_prekey": responder_onetime_prekey if responder_onetime_prekey else None,
    }


def encode_stealth_envelope(
    initiator_ed25519_pub: bytes,
    initiator_x25519_pub: bytes,
    initiator_x25519_identity_pub: bytes,
    initiator_device_id: bytes,
    signed_prekey_used: bytes,
    onetime_prekey_used: Optional[bytes],
    pq_ciphertext: Optional[bytes],
) -> bytes:
    out = bytearray()
    out.extend(initiator_ed25519_pub)
    out.extend(initiator_x25519_pub)
    out.extend(initiator_x25519_identity_pub)
    out.extend(initiator_device_id)
    out.extend(signed_prekey_used)
    if onetime_prekey_used is not None:
        out.extend(struct.pack("<I", len(onetime_prekey_used)))
        out.extend(onetime_prekey_used)
    else:
        out.extend(struct.pack("<I", 0))
    if pq_ciphertext is not None:
        out.extend(struct.pack("<I", len(pq_ciphertext)))
        out.extend(pq_ciphertext)
    else:
        out.extend(struct.pack("<I", 0))
    return bytes(out)


def decode_stealth_envelope(data: bytes) -> dict[str, Any]:
    offset = 0
    initiator_ed25519_pub = data[offset : offset + 32]
    offset += 32
    initiator_x25519_pub = data[offset : offset + 32]
    offset += 32
    initiator_x25519_identity_pub = data[offset : offset + 32]
    offset += 32
    initiator_device_id = data[offset : offset + 16]
    offset += 16
    signed_prekey_used = data[offset : offset + 32]
    offset += 32
    opk_len = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4
    onetime_prekey_used = data[offset : offset + opk_len]
    offset += opk_len
    pq_len = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4
    pq_ciphertext = data[offset : offset + pq_len]
    offset += pq_len
    return {
        "initiator_ed25519_pub": initiator_ed25519_pub,
        "initiator_x25519_pub": initiator_x25519_pub,
        "initiator_x25519_identity_pub": initiator_x25519_identity_pub,
        "initiator_device_id": initiator_device_id,
        "signed_prekey_used": signed_prekey_used,
        "onetime_prekey_used": onetime_prekey_used if onetime_prekey_used else None,
        "pq_ciphertext": pq_ciphertext if pq_ciphertext else None,
    }


# ── Handshake roles ─────────────────────────────────────────────────────────

from .session import Session  # noqa: E402  (imported at bottom to avoid circular import)
from .x3dh import PreKeyBundle, x3dh_initiator, x3dh_responder  # noqa: E402


async def initiator_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: Ed25519KeyPair,
    identity_x25519: X25519KeyPair,
    peer_bundle: PreKeyBundle,
    our_device_id: bytes = bytes(16),
    peer_device_id: bytes = bytes(16),
    timeout_secs: int = 30,
    expected_peer_identity: Optional[bytes] = None,
    use_pq: bool = False,
) -> tuple[Session, bytes]:
    """Run the initiator (Alice) side of the P2P handshake.

    Returns ``(session, peer_identity_key)`` where ``session`` is an established
    :class:`~sibna.session.Session` and ``peer_identity_key`` is the responder's
    Ed25519 public key.
    """
    # 1. Generate the single ephemeral key used for both transport and X3DH.
    alice_ephemeral = X25519KeyPair.generate()
    alice_ephemeral_pub = alice_ephemeral.public_key

    # 2. Send Hello.
    hello = Hello(
        version=P2P_PROTOCOL_VERSION,
        ephemeral_pub=alice_ephemeral_pub,
        initiator_device_id=our_device_id,
    )
    await _write_frame(writer, hello.encode())

    # 3. Receive Bundle.
    try:
        frame = await asyncio.wait_for(_read_frame(reader), timeout_secs)
    except asyncio.TimeoutError as exc:
        raise NetworkError("Handshake timed out waiting for Bundle") from exc
    bundle_msg = Bundle.decode(frame)
    bob_ephemeral_pub = bundle_msg.ephemeral_pub
    encrypted_bundle = bundle_msg.encrypted_bundle

    # Validate responder ephemeral key format (length only; DH will fail if invalid).
    if len(bob_ephemeral_pub) != C.X25519_PUBLIC_KEY_LENGTH:
        raise ProtocolError("Invalid responder ephemeral public key length")

    # 4. Derive transport key and decrypt the bundle.
    handler_key = derive_handshake_key(alice_ephemeral, bob_ephemeral_pub)
    bundle_nonce = encrypted_bundle[: C.NONCE_LENGTH]
    bundle_ct_and_tag = encrypted_bundle[C.NONCE_LENGTH :]
    bundle_payload = chacha20_poly1305_decrypt(
        handler_key, bundle_nonce + bundle_ct_and_tag, HANDSHAKE_BUNDLE_AD
    )

    stealth_bundle = decode_stealth_bundle(bundle_payload)

    # 5. Verify responder identity.
    if expected_peer_identity is not None:
        if stealth_bundle["responder_ed25519_pub"] != expected_peer_identity:
            raise ProtocolError("Peer identity mismatch — possible MITM")

    # 6. Transcript binding (matches X3DH internal transcript order).
    transcript_hash = build_transcript(
        identity.public_key,
        alice_ephemeral_pub,
        stealth_bundle["responder_ed25519_pub"],
        stealth_bundle["responder_x25519_pub"],
        stealth_bundle.get("responder_onetime_prekey"),
        our_device_id,
        stealth_bundle["responder_device_id"],
    )

    # 7. Run X3DH initiator.
    bob_spk = stealth_bundle["responder_signed_prekey"]
    bob_opk = stealth_bundle.get("responder_onetime_prekey")
    peer_bundle_py = PreKeyBundle(
        identity_key=stealth_bundle["responder_ed25519_pub"],
        x25519_identity_key=stealth_bundle["responder_x25519_pub"],
        signed_prekey=bob_spk,
        signed_prekey_signature=stealth_bundle["responder_signed_prekey_signature"],
        onetime_prekey=bob_opk,
        device_id=stealth_bundle["responder_device_id"],
    )
    result = x3dh_initiator(
        identity_keypair=identity_x25519,
        ephemeral_keypair=alice_ephemeral,
        peer_bundle=peer_bundle_py,
        our_device_id=our_device_id,
        peer_device_id=stealth_bundle["responder_device_id"],
        use_pq=use_pq,
    )

    # 8. Send Envelope (AEAD-encrypted StealthEnvelope).
    stealth_envelope = encode_stealth_envelope(
        initiator_ed25519_pub=identity.public_key,
        initiator_x25519_pub=alice_ephemeral.public_key,
        initiator_x25519_identity_pub=identity_x25519.public_key,
        initiator_device_id=our_device_id,
        signed_prekey_used=bob_spk,
        onetime_prekey_used=bob_opk,
        pq_ciphertext=result.pq_ciphertext,
    )
    await _encrypt_send(writer, handler_key, HANDSHAKE_ENVELOPE_AD, stealth_envelope)

    # 9. Receive Ok.
    try:
        frame = await asyncio.wait_for(_read_frame(reader), timeout_secs)
    except asyncio.TimeoutError as exc:
        raise NetworkError("Handshake timed out waiting for Ok") from exc
    envelope_payload = chacha20_poly1305_decrypt(
        handler_key,
        frame[: C.NONCE_LENGTH] + frame[C.NONCE_LENGTH :],
        HANDSHAKE_OK_AD,
    )

    # 10. Build the Double Ratchet session.
    remote_dh = bob_spk  # responder's signed prekey public key
    session = Session.from_shared_secret(
        shared_secret=result.shared_secret,
        local_dh_private=alice_ephemeral.private_key_bytes,
        remote_dh_public=bob_spk,
        role_is_initiator=True,
    )

    return session, stealth_bundle["responder_ed25519_pub"]


async def responder_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: Ed25519KeyPair,
    identity_x25519: X25519KeyPair,
    signed_prekey: X25519KeyPair,
    onetime_prekey: Optional[X25519KeyPair],
    our_device_id: bytes = bytes(16),
    timeout_secs: int = 30,
    expected_peer_identity: Optional[bytes] = None,
    use_pq: bool = False,
    our_pq_secret_key: Optional[bytes] = None,
    peer_pq_ciphertext: Optional[bytes] = None,
) -> tuple[Session, bytes]:
    """Run the responder (Bob) side of the P2P handshake.

    Returns ``(session, peer_identity_key)`` where ``session`` is an established
    :class:`~sibna.session.Session` and ``peer_identity_key`` is the initiator's
    Ed25519 public key.
    """
    # 1. Receive Hello.
    try:
        frame = await asyncio.wait_for(_read_frame(reader), timeout_secs)
    except asyncio.TimeoutError as exc:
        raise NetworkError("Handshake timed out waiting for Hello") from exc
    msg = Hello.decode(frame)
    alice_ephemeral_pub = msg.ephemeral_pub
    initiator_device_id = msg.initiator_device_id

    # Validate responder ephemeral key format (length only; DH will fail if invalid).
    if len(alice_ephemeral_pub) != C.X25519_PUBLIC_KEY_LENGTH:
        raise ProtocolError("Invalid initiator ephemeral public key length")

    # 2. Generate the single ephemeral key and send Bundle.
    bob_ephemeral = X25519KeyPair.generate()
    bob_ephemeral_pub = bob_ephemeral.public_key
    handler_key = derive_handshake_key(bob_ephemeral, alice_ephemeral_pub)

    # Build the stealth bundle directly from individual fields.
    stealth_bundle = {
        "responder_ed25519_pub": identity.public_key,
        "responder_x25519_pub": identity_x25519.public_key,
        "responder_device_id": our_device_id,
        "responder_signed_prekey": signed_prekey.public_key,
        "responder_onetime_prekey": onetime_prekey.public_key if onetime_prekey else None,
    }
    bundle_payload = encode_stealth_bundle(
        responder_ed25519_pub=identity.public_key,
        responder_x25519_pub=identity_x25519.public_key,
        responder_device_id=our_device_id,
        responder_signed_prekey=signed_prekey.public_key,
        responder_signed_prekey_signature=identity.sign(
            b"SibnaSignedPreKey_v3" + signed_prekey.public_key
        ),
        responder_onetime_prekey=onetime_prekey.public_key if onetime_prekey else None,
    )
    encrypted_bundle = chacha20_poly1305_encrypt(handler_key, bundle_payload, HANDSHAKE_BUNDLE_AD)
    bundle_msg = Bundle(ephemeral_pub=bob_ephemeral_pub, encrypted_bundle=encrypted_bundle)
    await _write_frame(writer, bundle_msg.encode())

    # 3. Receive Envelope.
    envelope_payload = await _decrypt_verify(reader, handler_key, HANDSHAKE_ENVELOPE_AD)
    stealth_envelope = decode_stealth_envelope(envelope_payload)

    # 4. Transcript binding (matches X3DH responder transcript order).
    transcript_hash = build_transcript(
        stealth_envelope["initiator_ed25519_pub"],
        alice_ephemeral_pub,
        identity.public_key,
        identity_x25519.public_key,
        onetime_prekey.public_key if onetime_prekey else None,
        initiator_device_id,
        our_device_id,
    )

    # 5. Run X3DH responder.
    result = x3dh_responder(
        identity_keypair=identity_x25519,
        signed_prekeypair=signed_prekey,
        onetime_prekeypair=onetime_prekey,
        peer_identity=stealth_envelope["initiator_x25519_identity_pub"],
        peer_ephemeral=alice_ephemeral_pub,
        our_device_id=our_device_id,
        peer_device_id=initiator_device_id,
        our_pq_secret_key=our_pq_secret_key,
        peer_pq_ciphertext=stealth_envelope.get("pq_ciphertext"),
    )

    # 6. Send Ok (AEAD-encrypted "OK").
    await _encrypt_send(writer, handler_key, HANDSHAKE_OK_AD, b"OK")

    # 7. Build the Double Ratchet session.
    remote_dh = alice_ephemeral_pub  # initiator's ephemeral public key
    session = Session.from_shared_secret(
        shared_secret=result.shared_secret,
        local_dh_private=signed_prekey.private_key_bytes,
        remote_dh_public=alice_ephemeral_pub,
        role_is_initiator=False,
    )

    return session, stealth_envelope["initiator_ed25519_pub"]


__all__ = [
    "P2pConfig",
    "P2pError",
    "NetworkError",
    "ProtocolError",
    "Hello",
    "Bundle",
    "Envelope",
    "Ok",
    "P2P_PROTOCOL_VERSION",
    "derive_handshake_key",
    "build_transcript",
    "encode_stealth_bundle",
    "decode_stealth_bundle",
    "encode_stealth_envelope",
    "decode_stealth_envelope",
    "initiator_handshake",
    "responder_handshake",
]
