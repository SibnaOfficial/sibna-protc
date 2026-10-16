"""
Sibna Python SDK — protocol and package version consistency tests.

Ensures the package version, protocol wire version, and minimum compatible
version are declared in one place and agree.
"""

from __future__ import annotations

from sibna import (
    HEADER_SIZE,
    MIN_COMPATIBLE_VERSION,
    PROTOCOL_VERSION_STRING,
    PROTOCOL_VERSION_WIRE,
    __version__,
)
from sibna import constants as C


def test_package_version():
    assert __version__ == "3.0.1"
    assert PROTOCOL_VERSION_STRING == "3.0.1"


def test_protocol_wire_versions():
    assert PROTOCOL_VERSION_WIRE == 10
    assert MIN_COMPATIBLE_VERSION == 9
    assert C.PROTOCOL_VERSION_WIRE == 10
    assert C.MIN_COMPATIBLE_VERSION == 9
    assert PROTOCOL_VERSION_WIRE > MIN_COMPATIBLE_VERSION


def test_ratchet_header_size():
    assert HEADER_SIZE == 56


def test_constants_constants_match():
    assert C.PROTOCOL_VERSION_WIRE == PROTOCOL_VERSION_WIRE
    assert C.MIN_COMPATIBLE_VERSION == MIN_COMPATIBLE_VERSION
