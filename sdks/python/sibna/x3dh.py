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

import struct
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

# NOTE on PQ hybrid ordering: both the published specification
# (PROTOCOL_SPECIFICATION.md §2.3) and the Rust core concatenate
# `dh1 || dh2 || dh3 || dh4 || ss_kem` for the PQ variant
# (`core/src/crypto/kdf.rs::derive_pq_shared_secret`). Python matches this
# ordering exactly. Both orderings are identical in the classical (non-PQ)
# case because ss_kem is absent. The spec and both implementations agree, so
# there is no ordering deviation to document.


@dataclass
class PreKeyBundle:
    """PreKeyBundle for X3DH handshake.

    Matches the Rust core wire format (core/src/handshake/mod.rs):
    signing_bytes() = identity_key(32) || signed_prekey(32) ||
                      signature(64) || has_onetime(1) || [onetime_prekey(32)] ||
                      bundle_id(16) || timestamp(8 LE) || expiration(8 LE) ||
                      device_id(4 LE) || root_identity_key(32) ||
                      device_signature(64)
    to_bytes() = signing_bytes() || bundle_signature(64)

    identity_key:            Ed25519 public key (32 bytes) — verifies SPK sig
                             AND device signature
    x25519_identity_key:     X25519 public key (32 bytes) — DH (NOT serialized;
                             used only in Python for X3DH DH2)
    signed_prekey:           X25519 public key (32 bytes) — DH
    signed_prekey_signature: Ed25519 signature (64 bytes) over SPK
    onetime_prekey:          X25519 public key (32 bytes, optional, single use)
    bundle_id:               16-byte unique bundle identifier
    timestamp:               uint64 LE creation timestamp
    expiration:              uint64 LE expiration timestamp
    device_id:               uint32 LE device identifier
    root_identity_key:       Ed25519 public key (32 bytes) — signs device binding
    device_signature:        Ed25519 signature (64 bytes) over
                             identity_key || device_id(LE)
    bundle_signature:        Ed25519 signature (64 bytes) over signing_bytes()
    pq_public_key:           ML-KEM-768 public key (1184 bytes, optional PQ)
    """

    identity_key: bytes
    x25519_identity_key: bytes
    signed_prekey: bytes
    signed_prekey_signature: bytes
    onetime_prekey: Optional[bytes] = None
    bundle_id: bytes = field(default_factory=lambda: bytes(16))
    timestamp: int = 0
    expiration: int = 0
    device_id: int = 0
    root_identity_key: bytes = field(default_factory=lambda: bytes(32))
    device_signature: bytes = field(default_factory=lambda: bytes(64))
    bundle_signature: bytes = field(default_factory=lambda: bytes(64))
    pq_public_key: Optional[bytes] = None
    pq_signed_prekey_signature: Optional[bytes] = None

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

    # ── Serialization (matches Rust core wire format) ──────────────────

    def signing_bytes(self) -> bytes:
        """Build the bytes that are signed by bundle_signature.

        Matches Rust `ServiceInfo::signing_bytes()`:
        identity_key(32) || signed_prekey(32) || signature(64) ||
        has_onetime(1) || [onetime_prekey(32)] || bundle_id(16) ||
        timestamp(8 LE) || expiration(8 LE) || device_id(4 LE) ||
        root_identity_key(32) || device_signature(64)
        """
        out = bytearray()
        out.extend(self.identity_key)
        out.extend(self.signed_prekey)
        out.extend(self.signed_prekey_signature)
        out.extend(struct.pack(">?", self.onetime_prekey is not None))
        if self.onetime_prekey is not None:
            out.extend(self.onetime_prekey)
        out.extend(self.bundle_id)
        out.extend(struct.pack("<Q", self.timestamp))
        out.extend(struct.pack("<Q", self.expiration))
        out.extend(struct.pack("<I", self.device_id))
        out.extend(self.root_identity_key)
        out.extend(self.device_signature)
        return bytes(out)

    def to_bytes(self) -> bytes:
        """Serialize to bytes matching Rust `ServiceInfo::to_bytes()`."""
        return self.signing_bytes() + self.bundle_signature

    @classmethod
    def from_bytes(cls, data: bytes) -> "PreKeyBundle":
        """Deserialize from bytes matching Rust `ServiceInfo::from_bytes()`."""
        # Minimum non-PQC size:
        # ik(32) + spk(32) + sig(64) + has_opk(1) + bundle_id(16) +
        # ts(8) + exp(8) + dev_id(4) + root(32) + dev_sig(64) + bundle_sig(64)
        # = 325 bytes
        if len(data) < 325:
            raise ValidationError("PreKeyBundle too short")

        # bundle_signature is always the last 64 bytes
        sig_start = len(data) - 64
        bundle_signature = data[sig_start:]
        data = data[:sig_start]

        offset = 0
        identity_key = data[offset : offset + 32]
        offset += 32

        signed_prekey = data[offset : offset + 32]
        offset += 32

        signature = data[offset : offset + 64]
        offset += 64

        has_onetime = data[offset] != 0
        offset += 1
        onetime_prekey = None
        if has_onetime:
            onetime_prekey = data[offset : offset + 32]
            offset += 32

        bundle_id = data[offset : offset + 16]
        offset += 16

        timestamp = struct.unpack("<Q", data[offset : offset + 8])[0]
        offset += 8

        expiration = struct.unpack("<Q", data[offset : offset + 8])[0]
        offset += 8

        device_id = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4

        root_identity_key = data[offset : offset + 32]
        offset += 32

        device_signature = data[offset : offset + 64]
        offset += 64

        # PQC fields (optional, only present if more data remains)
        pq_public_key = None
        pq_signed_prekey_signature = None
        if offset < len(data):
            has_pq = data[offset] != 0
            offset += 1
            if has_pq:
                pq_public_key = data[offset : offset + 1184]
                offset += 1184
                pq_signed_prekey_signature = data[offset : offset + 64]
                offset += 64

        return cls(
            identity_key=identity_key,
            x25519_identity_key=b"",  # Not serialized; set separately if needed
            signed_prekey=signed_prekey,
            signed_prekey_signature=signature,
            onetime_prekey=onetime_prekey,
            bundle_id=bundle_id,
            timestamp=timestamp,
            expiration=expiration,
            device_id=device_id,
            root_identity_key=root_identity_key,
            device_signature=device_signature,
            bundle_signature=bundle_signature,
            pq_public_key=pq_public_key,
            pq_signed_prekey_signature=pq_signed_prekey_signature,
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
    device_id_bytes: bytes = bytes(16),
    root_identity_key: Optional[bytes] = None,
    pq_keypair: Optional[tuple[bytes, bytes]] = None,
) -> PreKeyBundle:
    """Build a signed PreKeyBundle for publishing to a peer/relay.

    Signs ``b"SibnaSignedPreKey_v3" || signed_prekey.public`` with the Ed25519
    identity key (PROTOCOL_SPECIFICATION.md §2.2). Also signs the device
    binding (identity_key || device_id_LE) with the root identity key, and
    signs the full serialization with the device identity key.
    """
    if len(device_id_bytes) != C.DEVICE_ID_LENGTH:
        raise ValidationError("device_id must be 16 bytes")

    import time
    import uuid

    bundle_id = uuid.uuid4().bytes
    timestamp = int(time.time())
    expiration = timestamp + 30 * 86400  # 30 days
    device_id_u32 = int.from_bytes(device_id_bytes[:4], "little")

    # root_identity_key: if bytes, use as-is. If Ed25519KeyPair, extract public key.
    # If not provided, use identity_ed's public key.
    if root_identity_key is None:
        root_identity_key_bytes = identity_ed.public_key
        root_signer = identity_ed
    elif isinstance(root_identity_key, Ed25519KeyPair):
        root_identity_key_bytes = root_identity_key.public_key
        root_signer = root_identity_key
    else:
        root_identity_key_bytes = root_identity_key
        root_signer = identity_ed

    # Sign SPK: b"SibnaSignedPreKey_v3" || signed_prekey.public
    spk_signature = identity_ed.sign(C.SPK_SIGN_DOMAIN + signed_prekey.public_key)

    # Sign device binding: identity_key || device_id_LE with root identity key
    device_payload = identity_ed.public_key + device_id_bytes[:4]
    device_signature = root_signer.sign(device_payload)

    # Build bundle (without bundle_signature first)
    bundle = PreKeyBundle(
        identity_key=identity_ed.public_key,
        x25519_identity_key=identity_x25519.public_key,
        signed_prekey=signed_prekey.public_key,
        signed_prekey_signature=spk_signature,
        onetime_prekey=onetime_prekey.public_key if onetime_prekey else None,
        bundle_id=bundle_id,
        timestamp=timestamp,
        expiration=expiration,
        device_id=device_id_u32,
        root_identity_key=root_identity_key_bytes,
        device_signature=device_signature,
        bundle_signature=b"",
    )
    if pq_keypair is not None:
        # pq_keypair = (pk, sk)
        bundle.pq_public_key = pq_keypair[0]

    # Sign the full serialization with the device identity key
    signing_bytes = bundle.signing_bytes()
    bundle_signature = identity_ed.sign(signing_bytes)
    bundle.bundle_signature = bundle_signature

    return bundle


__all__ = [
    "PreKeyBundle",
    "X3DHResult",
    "x3dh_initiator",
    "x3dh_responder",
    "generate_peer_bundle",
]
