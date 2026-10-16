"""
Sibna Protocol v3.0.1 — Extended Triple Diffie-Hellman (X3DH).

Implements the X3DH handshake as specified in `PROTOCOL_SPECIFICATION.md`
§2 and as implemented by the Rust core
(`core/src/handshake/x3dh.rs`, `core/src/handshake/builder.rs`).

Key agreement:

    Initiator (Alice)                                              Responder (Bob)
    1. Fetch prekey bundle; verify SPK signature against IK_B.
    2. Generate random EK_A.
    3. [PQC] (ss_kem, ct_kem) = ML-KEM-768.Enc(SPK_B.pq_pk)
    4. DH:
         dh1 = DH(IK_A.x25519, SPK_B)
         dh2 = DH(EK_A, IK_B.x25519)
         dh3 = DH(EK_A, SPK_B)
         dh4 = DH(EK_A, OPK_B)  [if present]
    5. Transcript hash:
         T_internal = BLAKE3(IK_A || EK_A || IK_B || SPK_B || OPK_B ||
                              device_id_A || device_id_B)
         T = HKDF-Extract(salt=transcript_hash_ext, ikm=T_internal),
             expand with info="SibnaX3DH_TranscriptBind_v3"
    6. Session key:
         SK = HKDF-Extract(salt=T, ikm=dh1||dh2||dh3||dh4[||ss_kem]),
             expand with info="SibnaX3DH_v3" (non-PQ)
             or info="SibnaPQX3DH_v3" (PQ hybrid)

SPK signature (PROTOCOL_SPECIFICATION.md §2.2):

    spk_signature = Ed25519.Sign(IK_B.private, "SibnaSignedPreKey_v3" || SPK_B.public)

Bundles with an invalid SPK signature are rejected *before* any DH computation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import constants as C
from .crypto import (
    Ed25519KeyPair,
    X25519KeyPair,
    blake3_hash,
    hkdf,
    ml_kem_768_decapsulate,
    ml_kem_768_encapsulate,
    ml_kem_768_keypair,
)
from .errors import CryptoError, ValidationError

# NOTE on PQ hybrid ordering: the Rust core concatenates
# dh1 || dh2 || dh3 || dh4 || ss_kem for the PQ variant
# (`derive_pq_shared_secret`). The published spec §2.3 writes
# `ss_kem || dh1 || dh2 || dh3 || dh4`. To keep Python interoperable with the
# retained Rust implementation we match the Rust ordering exactly and document
# the deviation here. Both orderings are identical in the classical (non-PQ)
# case because ss_kem is absent.


@dataclass
class PreKeyBundle:
    """PreKeyBundle for X3DH handshake.

    identity_key:            Ed25519 public key (32 bytes) — verifies SPK sig
    x25519_identity_key:     X25519 public key (32 bytes) — DH
    signed_prekey:           X25519 public key (32 bytes) — DH
    signed_prekey_signature: Ed25519 signature (64 bytes) over SPK
    onetime_prekey:          X25519 public key (32 bytes, optional, single use)
    registration_id:         int
    device_id:               16-byte device identifier
    pq_public_key:           ML-KEM-768 public key (1184 bytes, optional PQ)
    """

    identity_key: bytes
    x25519_identity_key: bytes
    signed_prekey: bytes
    signed_prekey_signature: bytes
    onetime_prekey: Optional[bytes] = None
    registration_id: int = 0
    device_id: bytes = field(default_factory=lambda: bytes(16))
    pq_public_key: Optional[bytes] = None

    def verify_spk_signature(self) -> bool:
        """Verify the Ed25519 signature over the signed prekey.

        Signed bytes: ``b"SibnaSignedPreKey_v3" || signed_prekey``.
        """
        if len(self.identity_key) != C.ED25519_PUBLIC_KEY_LENGTH:
            return False
        if len(self.signed_prekey_signature) != C.ED25519_SIGNATURE_LENGTH:
            return False
        signed_payload = C.SPK_SIGN_DOMAIN + self.signed_prekey
        return Ed25519KeyPair.verify_with_key(
            self.identity_key, signed_payload, self.signed_prekey_signature
        )


@dataclass
class X3DHResult:
    """Result of X3DH key agreement."""

    shared_secret: bytes
    dh_results: list[bytes]
    pq_ciphertext: Optional[bytes] = None
    session_id: str = ""


def _validate_bundle_lengths(bundle: PreKeyBundle) -> None:
    if len(bundle.identity_key) != C.ED25519_PUBLIC_KEY_LENGTH:
        raise ValidationError("identity_key must be 32 bytes")
    if len(bundle.x25519_identity_key) != C.X25519_PUBLIC_KEY_LENGTH:
        raise ValidationError("x25519_identity_key must be 32 bytes")
    if len(bundle.signed_prekey) != C.X25519_PUBLIC_KEY_LENGTH:
        raise ValidationError("signed_prekey must be 32 bytes")
    if (
        bundle.onetime_prekey is not None
        and len(bundle.onetime_prekey) != C.X25519_PUBLIC_KEY_LENGTH
    ):
        raise ValidationError("onetime_prekey must be 32 bytes")
    if (
        bundle.pq_public_key is not None
        and len(bundle.pq_public_key) != C.ML_KEM_768_PUBLIC_KEY_LENGTH
    ):
        raise ValidationError("pq_public_key must be 1184 bytes")


def _device_id_bytes(device_id: bytes) -> bytes:
    if len(device_id) != C.DEVICE_ID_LENGTH:
        raise ValidationError(f"device_id must be {C.DEVICE_ID_LENGTH} bytes, got {len(device_id)}")
    return device_id


def x3dh_initiator(
    identity_keypair: X25519KeyPair,
    ephemeral_keypair: X25519KeyPair,
    peer_bundle: PreKeyBundle,
    our_device_id: bytes = bytes(16),
    peer_device_id: bytes = bytes(16),
    transcript_hash_ext: bytes = bytes(32),
    use_pq: bool = False,
) -> X3DHResult:
    """X3DH key agreement — initiator side.

    Verifies the peer's signed-prekey signature *before* any DH computation.
    Raises CryptoError on invalid signature.
    """
    _validate_bundle_lengths(peer_bundle)
    _device_id_bytes(our_device_id)
    _device_id_bytes(peer_device_id)

    # --- 1. Verify SPK signature before DH (spec §2.2) -------------------
    if not peer_bundle.verify_spk_signature():
        raise CryptoError("Invalid signed prekey signature — rejecting bundle")

    # --- 2. DH computations ---------------------------------------------
    dh1 = identity_keypair.dh(peer_bundle.signed_prekey)
    dh2 = ephemeral_keypair.dh(peer_bundle.x25519_identity_key)
    dh3 = ephemeral_keypair.dh(peer_bundle.signed_prekey)

    dh_results = [dh1, dh2, dh3]
    dh4 = None
    if peer_bundle.onetime_prekey:
        dh4 = ephemeral_keypair.dh(peer_bundle.onetime_prekey)
        dh_results.append(dh4)

    # --- 3. Transcript hash (public keys only) --------------------------
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

    combined_transcript = hkdf(
        transcript_hash,
        salt=transcript_hash_ext,
        info=C.X3DH_TRANSCRIPT_BIND_INFO,
        length=C.KEY_LENGTH,
    )

    # --- 4. [PQC] ML-KEM-768 encapsulation ------------------------------
    pq_ct = None
    pq_ss = None
    if use_pq:
        if peer_bundle.pq_public_key is None:
            raise CryptoError("PQ hybrid required but peer has no ML-KEM-768 key")
        pq_ct, pq_ss = ml_kem_768_encapsulate(peer_bundle.pq_public_key)

    # --- 5. Derive shared secret ----------------------------------------
    concatenated = dh1 + dh2 + dh3
    if dh4 is not None:
        concatenated += dh4
    if pq_ss is not None:
        # Match Rust core ordering: dh1||dh2||dh3||dh4||ss_kem
        concatenated += pq_ss

    if pq_ss is not None:
        shared_secret = hkdf(
            concatenated,
            salt=combined_transcript,
            info=C.X3DH_PQ_SHARED_SECRET_INFO,
            length=C.KEY_LENGTH,
        )
    else:
        shared_secret = hkdf(
            concatenated,
            salt=combined_transcript,
            info=C.X3DH_SHARED_SECRET_INFO,
            length=C.KEY_LENGTH,
        )

    return X3DHResult(
        shared_secret=shared_secret,
        dh_results=dh_results,
        pq_ciphertext=pq_ct,
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
    our_pq_secret_key: Optional[bytes] = None,
    peer_pq_ciphertext: Optional[bytes] = None,
) -> X3DHResult:
    """X3DH key agreement — responder side.

    DH:
        dh1 = DH(our SPK, peer IK)
        dh2 = DH(our IK, peer EK)
        dh3 = DH(our SPK, peer EK)
        dh4 = DH(our OPK, peer EK)  [if present]
    """
    if len(peer_identity) != C.X25519_PUBLIC_KEY_LENGTH:
        raise ValidationError("peer_identity must be 32 bytes")
    if len(peer_ephemeral) != C.X25519_PUBLIC_KEY_LENGTH:
        raise ValidationError("peer_ephemeral must be 32 bytes")
    _device_id_bytes(our_device_id)
    _device_id_bytes(peer_device_id)

    # --- 1. DH computations (responder perspective) ---------------------
    dh1 = signed_prekeypair.dh(peer_identity)
    dh2 = identity_keypair.dh(peer_ephemeral)
    dh3 = signed_prekeypair.dh(peer_ephemeral)

    dh_results = [dh1, dh2, dh3]
    dh4 = None
    if onetime_prekeypair is not None:
        dh4 = onetime_prekeypair.dh(peer_ephemeral)
        dh_results.append(dh4)

    # --- 2. Transcript hash (responder view; order matches initiator) --
    # Initiator order: [our_id, our_eph, peer_id, peer_spk, opk, our_dev,
    #                   peer_dev]. From responder's view:
    # [peer_id, peer_eph, our_id, our_spk, opt(our_opk), peer_dev, our_dev].
    parts = [
        peer_identity,
        peer_ephemeral,
        identity_keypair.public_key,
        signed_prekeypair.public_key,
    ]
    if onetime_prekeypair is not None:
        parts.append(onetime_prekeypair.public_key)
    parts.extend([peer_device_id, our_device_id])
    transcript_hash = blake3_hash(*parts)

    combined_transcript = hkdf(
        transcript_hash,
        salt=transcript_hash_ext,
        info=C.X3DH_TRANSCRIPT_BIND_INFO,
        length=C.KEY_LENGTH,
    )

    # --- 3. [PQC] ML-KEM-768 decapsulation ------------------------------
    pq_ss = None
    if our_pq_secret_key is not None and peer_pq_ciphertext is not None:
        pq_ss = ml_kem_768_decapsulate(our_pq_secret_key, peer_pq_ciphertext)

    # --- 4. Derive shared secret ----------------------------------------
    concatenated = dh1 + dh2 + dh3
    if dh4 is not None:
        concatenated += dh4
    if pq_ss is not None:
        concatenated += pq_ss

    if pq_ss is not None:
        shared_secret = hkdf(
            concatenated,
            salt=combined_transcript,
            info=C.X3DH_PQ_SHARED_SECRET_INFO,
            length=C.KEY_LENGTH,
        )
    else:
        shared_secret = hkdf(
            concatenated,
            salt=combined_transcript,
            info=C.X3DH_SHARED_SECRET_INFO,
            length=C.KEY_LENGTH,
        )

    return X3DHResult(
        shared_secret=shared_secret,
        dh_results=dh_results,
    )


def generate_peer_bundle(
    identity_ed: Ed25519KeyPair,
    identity_x25519: X25519KeyPair,
    signed_prekey: X25519KeyPair,
    onetime_prekey: Optional[X25519KeyPair] = None,
    device_id: bytes = bytes(16),
    pq_keypair: Optional[tuple[bytes, bytes]] = None,
) -> PreKeyBundle:
    """Build a signed PreKeyBundle for publishing to a peer/relay.

    Signs ``b"SibnaSignedPreKey_v3" || signed_prekey.public`` with the Ed25519
    identity key.
    """
    if len(device_id) != C.DEVICE_ID_LENGTH:
        raise ValidationError("device_id must be 16 bytes")
    # Signs b"SibnaSignedPreKey_v3" || signed_prekey.public with the Ed25519
    # identity key (PROTOCOL_SPECIFICATION.md §2.2).
    signature = identity_ed.sign(C.SPK_SIGN_DOMAIN + signed_prekey.public_key)
    bundle = PreKeyBundle(
        identity_key=identity_ed.public_key,
        x25519_identity_key=identity_x25519.public_key,
        signed_prekey=signed_prekey.public_key,
        signed_prekey_signature=signature,
        onetime_prekey=onetime_prekey.public_key if onetime_prekey else None,
        device_id=device_id,
    )
    if pq_keypair is not None:
        # pq_keypair = (pk, sk)
        bundle.pq_public_key = pq_keypair[0]
    return bundle


__all__ = [
    "PreKeyBundle",
    "X3DHResult",
    "x3dh_initiator",
    "x3dh_responder",
    "generate_peer_bundle",
]
