"""
Sibna Protocol v3.0.1 — Message padding for metadata resistance.

Wire-compatible with the Rust core (`core/src/crypto/padding.rs`).

Format (v3.1):

    [ prefix_len(1) | prefix_noise(1..8) | plaintext | random_padding |
      pad_len(2, little-endian) ]

Total output length is always a multiple of the block size (1024 bytes for
``PaddingMode.Standard``).

Per SIBNA-2026-018, the per-block suffix length is randomized: 0..MAX_EXTRA_BLOCKS
(7) additional full blocks are appended so two messages of identical plaintext
length do not necessarily produce the same on-wire size. The trailing 2-byte LE
field lets ``unpad_message`` recover the exact plaintext.

Padding does NOT replace encryption, authentication, or end-to-end
confidentiality. It only hides message size from network observers.
"""

from __future__ import annotations

import os
from typing import Literal

from . import constants as C
from .errors import CryptoError, ValidationError


class PaddingMode:
    """Padding strategies (mirrors Rust ``PaddingMode``)."""

    None_ = "none"  # no padding — leaks exact message size
    Small = "small"  # 256-byte blocks
    Standard = "standard"  # 1024-byte blocks (recommended default)
    Large = "large"  # 4096-byte blocks
    Maximum = "maximum"  # 16384-byte blocks
    Quantum = "quantum"  # 65536-byte blocks

    @classmethod
    def block_size(cls, mode: str) -> int:
        table = {
            cls.None_: 1,
            cls.Small: 256,
            cls.Standard: 1024,
            cls.Large: 4096,
            cls.Maximum: 16384,
            cls.Quantum: 65536,
        }
        if mode not in table:
            raise ValidationError(f"Unknown padding mode: {mode!r}")
        return table[mode]

    @classmethod
    def is_enabled(cls, mode: str) -> bool:
        return mode != cls.None_


PADDING_MIN_OVERHEAD = 1 + 1 + 2  # prefix_len(1) + prefix_noise(min 1) + pad_len(2)
MAX_PADDING_BYTES = C.MAX_PADDING_BYTES


def pad_message(plaintext: bytes, mode: str = PaddingMode.Standard) -> bytes:
    """Pad ``plaintext`` to a multiple of the block size.

    Returns a buffer whose length is a multiple of ``block_size(mode)``.
    Empty plaintext is allowed (carrier for cover/dummy traffic).
    """
    block = PaddingMode.block_size(mode)

    # Empty plaintext still pads to a single block (a fixed-size dummy
    # indistinguishable from a real message), except Quantum mode which
    # may carry a true zero-length padding structure.
    rng = os.urandom

    # 1. Random prefix noise (1 to 8 bytes)
    prefix_len = rng(1)[0] % 8 + 1
    prefix_noise = rng(prefix_len)

    min_total = 1 + prefix_len + len(plaintext) + 2
    remainder = min_total % block
    min_pad_len = (block - remainder) % block

    # 2. SIBNA-2026-018: randomize suffix length (0..MAX_EXTRA_BLOCKS extra
    #    full blocks), capped so pad_len fits in the 2-byte length field.
    max_blocks_for_budget = (MAX_PADDING_BYTES - min_pad_len) // block
    cap = min(C.MAX_EXTRA_BLOCKS, max_blocks_for_budget)
    extra_blocks = rng(1)[0] % (cap + 1)
    pad_len = min_pad_len + extra_blocks * block

    if pad_len > MAX_PADDING_BYTES:
        raise CryptoError(f"Computed pad_len {pad_len} exceeds max {MAX_PADDING_BYTES}")

    output = bytearray()
    output.append(prefix_len)
    output.extend(prefix_noise)
    output.extend(plaintext)
    if pad_len > 0:
        output.extend(rng(pad_len))
    output.append(pad_len & 0xFF)
    output.append((pad_len >> 8) & 0xFF)

    return bytes(output)


def unpad_message(padded: bytes) -> bytes:
    """Remove padding and recover the original plaintext."""
    if len(padded) < PADDING_MIN_OVERHEAD:
        raise CryptoError("Payload too short to unpad")

    prefix_len = padded[0]
    if not (1 <= prefix_len <= 8):
        raise CryptoError(f"Invalid prefix length: {prefix_len}")
    if 1 + prefix_len + 2 > len(padded):
        raise CryptoError("Invalid padding layout")

    # Trailing 2-byte LE pad length
    pad_len = padded[-2] | (padded[-1] << 8)

    total_overhead = 1 + prefix_len + pad_len + 2
    if total_overhead > len(padded):
        raise CryptoError("Invalid padding: overhead exceeds payload length")

    plaintext_len = len(padded) - total_overhead
    start = 1 + prefix_len
    end = start + plaintext_len
    return padded[start:end]


# Backward-compatible aliases matching the previous Python SDK names.
pad_payload = pad_message
unpad_payload = unpad_message


__all__ = [
    "PaddingMode",
    "PADDING_MIN_OVERHEAD",
    "MAX_PADDING_BYTES",
    "pad_message",
    "unpad_message",
    "pad_payload",
    "unpad_payload",
]
