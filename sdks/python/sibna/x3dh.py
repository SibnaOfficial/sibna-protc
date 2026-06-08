"""
Sibna Protocol v3.0.1 — Extended Triple Diffie-Hellman (X3DH)

Matches the Rust core implementation exactly:
  - Transcript hash via Blake3 (fallback SHA-256)
  - HKDF-based transcript binding with "SibnaX3DH_TranscriptBind_v3"
  - Shared secret derivation via HKDF with "SibnaX3DH_v3"
  - DH computation order: initiator and responder perspectives
  - X25519 identity key for DH, Ed25519 identity key for signing
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .crypto import (
    KEY_LENGTH,
    X25519KeyPair,
    blake3_hash,
    hkdf,
)


@dataclass
class PreKeyBundle:
    """
    PreKeyBundle for X3DH handshake.

    identity_key: Ed25519 public key (32 bytes) — used for signature verification
    x25519_identity_key: X25519 public key (32 bytes) — used for DH in X3DH
    signed_prekey: X25519 public key (32 bytes) — used for DH
    signed_prekey_signature: Ed25519 signature (64 bytes) — over signed_prekey
    """

    identity_key: bytes  # Ed25519 public key (32 bytes)
    x25519_identity_key: bytes  # X25519 public key (32 bytes) — for DH
    signed_prekey: bytes  # X25519 public key (32 bytes)
    signed_prekey_signature: bytes  # Ed25519 signature (64 bytes)
    onetime_prekey: Optional[bytes] = None  # X25519 public key (32 bytes, optional)
    registration_id: int = 0
    device_id: int = 0

    @property
    def is_expired(self) -> bool:
        """Check if the bundle has expired. Standalone bundles never expire."""
        return False


@dataclass
class X3DHResult:
    """Result of X3DH key agreement."""

    shared_secret: bytes  # 32-byte derived shared secret
    dh_results: list  # List of raw DH outputs
    session_id: str = ""


def x3dh_initiator(
    identity_keypair: X25519KeyPair,
    ephemeral_keypair: X25519KeyPair,
    peer_bundle: PreKeyBundle,
    our_device_id: bytes = bytes(16),
    peer_device_id: bytes = bytes(16),
    transcript_hash_ext: bytes = bytes(32),
) -> X3DHResult:
    """
    X3DH key agreement — initiator side.

    DH1 = DH(our_identity_x25519, peer_spk)
    DH2 = DH(our_ephemeral, peer_identity_x25519)
    DH3 = DH(our_ephemeral, peer_spk)
    DH4 = DH(our_ephemeral, peer_opk)  [optional]
    """
    # DH computations — using X25519 identity key for DH (not Ed25519)
    dh1 = identity_keypair.dh(peer_bundle.signed_prekey)
    dh2 = ephemeral_keypair.dh(peer_bundle.x25519_identity_key)
    dh3 = ephemeral_keypair.dh(peer_bundle.signed_prekey)

    dh_results = [dh1, dh2, dh3]
    dh4 = None
    if peer_bundle.onetime_prekey:
        dh4 = ephemeral_keypair.dh(peer_bundle.onetime_prekey)
        dh_results.append(dh4)

    # Transcript hash (only PUBLIC keys — matching Rust x3dh_initiator_v3)
    # Order: [our_id, our_eph, peer_id, peer_spk, opt(peer_opk), our_dev, peer_dev]
    parts = [
        identity_keypair.public_key,
        ephemeral_keypair.public_key,
        peer_bundle.x25519_identity_key,
        peer_bundle.signed_prekey,
    ]
    if peer_bundle.onetime_prekey:
        parts.append(peer_bundle.onetime_prekey)
    parts.extend([our_device_id, peer_device_id])
    transcript_hash = blake3_hash(*parts)

    # HKDF-based transcript binding
    combined_transcript = hkdf(
        transcript_hash,
        salt=transcript_hash_ext,
        info=b"SibnaX3DH_TranscriptBind_v3",
        length=32,
    )

    # Derive shared secret
    shared_secret = _derive_shared_secret(dh1, dh2, dh3, dh4, combined_transcript)

    return X3DHResult(
        shared_secret=shared_secret,
        dh_results=dh_results,
    )


def x3dh_responder(
    identity_keypair: X25519KeyPair,
    signed_prekeypair: X25519KeyPair,
    onetime_prekeypair: Optional[X25519KeyPair],
    peer_identity: bytes,
    peer_ephemeral: bytes,
    our_device_id: bytes = bytes(16),
    peer_device_id: bytes = bytes(16),
    transcript_hash_ext: bytes = bytes(32),
) -> X3DHResult:
    """
    X3DH key agreement — responder side.

    DH1 = DH(our_spk, peer_identity)
    DH2 = DH(our_identity, peer_ephemeral)
    DH3 = DH(our_spk, peer_ephemeral)
    DH4 = DH(our_opk, peer_ephemeral)  [optional]
    """
    # DH computations (note: perspective is reversed from initiator)
    dh1 = signed_prekeypair.dh(peer_identity)
    dh2 = identity_keypair.dh(peer_ephemeral)
    dh3 = signed_prekeypair.dh(peer_ephemeral)

    dh_results = [dh1, dh2, dh3]
    dh4 = None
    if onetime_prekeypair:
        dh4 = onetime_prekeypair.dh(peer_ephemeral)
        dh_results.append(dh4)

    # Transcript hash (matching Rust x3dh_responder_v3 order)
    # From responder's view: [peer_id, peer_eph, our_id, our_spk, opt(our_opk), peer_dev, our_dev]
    parts = [
        peer_identity,
        peer_ephemeral,
        identity_keypair.public_key,
        signed_prekeypair.public_key,
    ]
    if onetime_prekeypair:
        parts.append(onetime_prekeypair.public_key)
    parts.extend([peer_device_id, our_device_id])
    transcript_hash = blake3_hash(*parts)

    # HKDF-based transcript binding
    combined_transcript = hkdf(
        transcript_hash,
        salt=transcript_hash_ext,
        info=b"SibnaX3DH_TranscriptBind_v3",
        length=32,
    )

    # Derive shared secret
    shared_secret = _derive_shared_secret(dh1, dh2, dh3, dh4, combined_transcript)

    return X3DHResult(
        shared_secret=shared_secret,
        dh_results=dh_results,
    )


def _derive_shared_secret(
    dh1: bytes,
    dh2: bytes,
    dh3: bytes,
    dh4: Optional[bytes],
    transcript_hash: bytes,
) -> bytes:
    """
    Derive X3DH shared secret from DH outputs.
    Matches Rust X3dhKdf::derive_shared_secret().
    """
    concatenated = dh1 + dh2 + dh3
    if dh4 is not None:
        concatenated += dh4

    return hkdf(
        concatenated,
        salt=transcript_hash,
        info=b"SibnaX3DH_v3",
        length=KEY_LENGTH,
    )
