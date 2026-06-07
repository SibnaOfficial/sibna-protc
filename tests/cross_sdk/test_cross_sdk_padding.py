#!/usr/bin/env python3
"""
Cross-SDK Padding Compatibility Test

This test validates that all SDKs implement the same padding wire format.
Run with: python -m pytest tests/cross_sdk/test_cross_sdk_padding.py -v

Currently validates Python implementation against hand-built Rust fixtures.
Extend to call other SDKs via subprocess/FFI when available.
"""

import json
import sys
from pathlib import Path

# Add Python SDK to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "sdks" / "python"))

from sibna.client import pad_payload, unpad_payload, CryptoError

VECTORS_FILE = Path(__file__).parent / "padding_vectors.json"


def load_vectors():
    with open(VECTORS_FILE) as f:
        return json.load(f)


def test_python_pad_unpad_roundtrip():
    """Python pad -> Python unpad roundtrip for all vectors."""
    vectors = load_vectors()
    for vec in vectors["vectors"]:
        if "plaintext_hex" in vec:
            plaintext = bytes.fromhex(vec["plaintext_hex"])
            if "repeat" in vec:
                plaintext = plaintext * vec["repeat"]
        elif "repeat" in vec:
            # For vectors with just repeat
            plaintext = bytes([0]) * vec["repeat"]
        else:
            continue

        padded = pad_payload(plaintext)
        assert len(padded) % 1024 == 0, f"{vec['name']}: not block-aligned"

        unpadded = unpad_payload(padded)
        assert unpadded == plaintext, f"{vec['name']}: roundtrip failed"


def test_python_unpads_rust_fixture():
    """Python unpad must correctly decode the hand-built Rust fixture.

    Fixture: prefix_len=3, prefix_noise=AA BB CC, plaintext="hello",
    pad_len=1013 (so total = 1024), trailing LE pad_len=0x03F5.
    """
    # Build the Rust-compatible fixture
    prefix_len = 3
    prefix_noise = bytes.fromhex("aabbcc")
    plaintext = b"hello"
    pad_len = 1013  # 1024 - (1 + 3 + 5 + 2) = 1013
    padded = (
        bytes([prefix_len]) +
        prefix_noise +
        plaintext +
        bytes(pad_len) +
        pad_len.to_bytes(2, 'little')
    )
    assert len(padded) == 1024

    unpadded = unpad_payload(padded)
    assert unpadded == plaintext


def test_python_size_distribution():
    """SIBNA-2026-018: 64 trials must yield >= 2 distinct sizes."""
    plaintext = b"constant-size message"
    sizes = set()
    for _ in range(64):
        padded = pad_payload(plaintext)
        assert len(padded) % 1024 == 0
        sizes.add(len(padded))
    assert len(sizes) >= 2, f"Only {len(sizes)} distinct sizes: {sizes}"


def test_python_prefix_len_range():
    """prefix_len must be in [1, 8] on every call."""
    for _ in range(32):
        padded = pad_payload(b"ping")
        assert 1 <= padded[0] <= 8


if __name__ == "__main__":
    test_python_pad_unpad_roundtrip()
    test_python_unpads_rust_fixture()
    test_python_size_distribution()
    test_python_prefix_len_range()
    print("All cross-SDK padding tests passed!")