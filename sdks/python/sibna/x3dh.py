def prekey_bundle_from_bytes(data: bytes) -> PreKeyBundle:
    """Deserialize a PreKeyBundle from the Rust wire format.

    Matches ``PreKeyBundle::from_bytes()`` from the Rust core.
    The Rust wire format does not serialize ``x25519_identity_key`` — it is
    not present on the wire. Callers must obtain the correct X25519 identity
    public key from their X3DH context (e.g. from a separately exchanged
    identity key, or from ``generate_peer_bundle()``) before calling
    ``x3dh_initiator()``, which uses this key for DH computation.

    This function sets ``x25519_identity_key`` to ``bytes(32)`` as a
    placeholder. It does NOT raise ValidationError for the placeholder,
    since the wire format does not contain this field — callers must
    provide the correct key from the X3DH context.
    """
    import struct

    if len(data) < 325:  # minimum: no PQ + fixed fields
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
    # device_id: convert int to 4 bytes LE (wire format), pad to 16 bytes for dataclass
    device_id = struct.pack("<I", device_id_int).ljust(16, b"\x00")
    # root_identity_key (32)
    root_identity_key = data[offset : offset + 32]
    offset += 32
    # device_signature (64)
    device_signature = data[offset : offset + 64]
    offset += 64

    # pq_public_key and pq_signed_prekey_signature are not part of the
    # non-PQ wire format; they are ignored here (the caller must handle
    # PQ bundles separately if needed).

    # x25519_identity_key: not present in the Rust wire format.
    # Set as placeholder bytes(32); callers must obtain the correct key
    # from the X3DH context (e.g. from generate_peer_bundle()).
    x25519_identity_key = bytes(32)

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
        bundle_signature=bytes(64),  # will be verified separately if needed
    )
    return bundle