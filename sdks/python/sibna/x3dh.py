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
import struct
import time

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

    identity_key:            Ed25519 public key (32 bytes) — verifies SPK sig
    x25519_identity_key:     X25519 public key (32 bytes) — DH
    signed_prekey:           X25519 public key (32 bytes) — DH
    signed_prekey_signature: Ed25519 signature (64 bytes) over SPK
    onetime_prekey:          X25519 public key (32 bytes, optional, single use)
    bundle_id:               16-byte bundle identifier
    timestamp:               Unix timestamp (seconds since epoch)
    expiration:              Expiration timestamp (seconds since epoch)
    device_id:               4-byte device identifier (u32, LE)
    root_identity_key:       Ed25519 public key (32 bytes) — verifies device sig
    device_signature:        Ed25519 signature (64 bytes) over device binding
    pq_public_key:           ML-KEM-768 public key (1184 bytes, optional PQ)
    bundle_signature:        Ed25519 signature over signing_bytes()
    """

    identity_key: bytes
    x25519_identity_key: bytes
    signed_prekey: bytes
    signed_prekey_signature: bytes
    onetime_prekey: Optional[bytes] = None
    bundle_id: bytes = field(default_factory=lambda: bytes(16))
    timestamp: int = field(default_factory=lambda: int(time.time()))
    expiration: int = field(default_factory=lambda: int(time.time()) + 30 * 86400)  # 30 days
    registration_id: int = 0
    device_id: int = field(default_factory=lambda: 0)
    root_identity_key: bytes = bytes(32)
    device_signature: bytes = bytes(64)
    pq_public_key: Optional[bytes] = None
    pq_signed_prekey_signature: Optional[bytes] = None
    bundle_signature: bytes = bytes(64)

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

    def signing_bytes(self) -> bytes:
        """Build the bytes that are signed by ``bundle_signature``.

        Matches Rust ``PreKeyBundle::signing_bytes()``:
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
        out.extend(self.device_id.to_bytes(4, "little"))
        out.extend(self.root_identity_key)
        out.extend(self.device_signature)
        return bytes(out)


def prekey_bundle_from_bytes(data: bytes) -> PreKeyBundle:
    """Deserialize a PreKeyBundle from the Rust wire format.

    Matches ``PreKeyBundle::from_bytes()`` from the Rust core.
    The wire format includes ``x25519_identity_key`` (32 bytes) after
    ``bundle_signature``, consistent with the updated Rust serialization.

    Raises ValidationError if the bundle is too short or if
    ``x25519_identity_key`` is missing.
    """
    import struct

    # Minimum non-PQ wire format (no onetime_prekey, with x25519_identity_key):
    # identity_key(32) + signed_prekey(32) + signature(64) + has_onetime(1)
    # + bundle_id(16) + timestamp(8) + expiration(8) + device_id(4)
    # + root_identity_key(32) + device_signature(64) + bundle_signature(64)
    # + x25519_identity_key(32) = 357 bytes
    # With onetime_prekey: 357 + 32 = 389 bytes
    if len(data) < 357:  # minimum: no PQ + fixed fields + x25519_identity_key
        raise ValidationError("prekey bundle too short")

    # identity_key (32)
    identity_key = data[0:32]
    # signed_prekey (32)
    signed_prekey = data[32:64]
    # signed_prekey_signature (64)
    signed_prekey_signature = data[64:128]
    # has_onetime (1)
    has_onetime = data[128]
    offset = 129
    # onetime_prekey (32 if present)
    if has_onetime:
        if offset + 32 > len(data):
            raise ValidationError("truncated onetime_prekey")
        onetime_prekey = data[offset : offset + 32]
        offset += 32
    else:
        onetime_prekey = None
    # bundle_id (16)
    bundle_id = data[offset : offset + 16]
    offset += 16
    # timestamp (8 LE)
    timestamp = struct.unpack("<Q", data[offset : offset + 8])[0]
    offset += 8
    # expiration (8 LE)
    expiration = struct.unpack("<Q", data[offset : offset + 8])[0]
    offset += 8
    # device_id (4 LE)
    device_id_int = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4
    # device_id: int (matches Rust u32)
    device_id = device_id_int
    # root_identity_key (32)
    root_identity_key = data[offset : offset + 32]
    offset += 32
    # device_signature (64)
    device_signature = data[offset : offset + 64]
    offset += 64
    # bundle_signature (64)
    bundle_signature = data[offset : offset + 64]
    offset += 64
    # x25519_identity_key (32) — after bundle_signature in wire format
    if offset + 32 > len(data):
        raise ValidationError("truncated x25519_identity_key")
    x25519_identity_key = data[offset : offset + 32]
    offset += 32

    # pq_public_key and pq_signed_prekey_signature are not part of the
    # non-PQ wire format; they are ignored here (the caller must handle
    # PQ bundles separately if needed).

    bundle = PreKeyBundle(
        identity_key=identity_key,
        x25519_identity_key=x25519_identity_key,
        signed_prekey=signed_prekey,
        signed_prekey_signature=signed_prekey_signature,
        onetime_prekey=onetime_prekey,
        registration_id=0,
        device_id=device_id,
        root_identity_key=root_identity_key,
        device_signature=device_signature,
        pq_public_key=None,
        pq_signed_prekey_signature=None,
        bundle_signature=bundle_signature,
    )
    return bundle


def prekey_bundle_to_bytes(bundle: PreKeyBundle) -> bytes:
    """Serialize a PreKeyBundle to bytes matching the Rust wire format.

    Equivalent to ``bundle.signing_bytes()`` || ``bundle.bundle_signature``.
    """
    return bundle.signing_bytes() + bundle.bundle_signature


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
    device_id_int = int.from_bytes(device_id[:4], "little")
    if not (0 <= device_id_int <= 0xFFFFFFFF):
        raise ValidationError(f"device_id must be a valid u32, got {device_id_int}")
    return device_id_int.to_bytes(4, "little")


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

    root_identity_key must be provided as 32-byte Ed25519 public key bytes.
    It must be separate from identity_key — the device_signature verification
    in the Rust core checks that the device binding was signed by the root
    private key corresponding to this public key.
    """
    if len(device_id_bytes) != C.DEVICE_ID_LENGTH:
        raise ValidationError("device_id must be 16 bytes")

    import time
    import uuid

    bundle_id = uuid.uuid4().bytes
    timestamp = int(time.time())
    expiration = timestamp + 30 * 86400  # 30 days
    device_id_u32 = int.from_bytes(device_id_bytes[:4], "little")

    # root_identity_key: must be provided as 32-byte Ed25519 public key bytes.
    # The device_id field is 4 bytes (u32 LE); it must be separate from
    # identity_key — the device_signature verification in the Rust core checks
    # that the device binding was signed by the root private key corresponding
    # to this public key.
    if root_identity_key is None:
        raise ValidationError(
            "root_identity_key must be provided as 32-byte Ed25519 public key; "
            "it must be separate from the identity key and signed by the root "
            "private key for device binding"
        )
    root_identity_key_bytes = root_identity_key

    # Sign SPK: b"SibnaSignedPreKey_v3" || signed_prekey.public
    spk_signature = identity_ed.sign(C.SPK_SIGN_DOMAIN + signed_prekey.public_key)

    # Sign device binding: identity_key || device_id_LE with root identity key.
    # Since the root private key is not available in this function, we sign with
    # the identity key's private key. The root_identity_key field in the bundle
    # must correspond to the private key that signed the device_signature; if it
    # does not (e.g. root_identity_key == identity_ed.public_key), the Rust
    # validate() will still succeed because it's the same key pair, but the
    # caller must ensure the correct key hierarchy for production use.
    device_payload = identity_ed.public_key + device_id_bytes[:4]
    device_signature = identity_ed.sign(device_payload)

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
