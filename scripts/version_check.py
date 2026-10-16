#!/usr/bin/env python3
"""
Sibna Protocol — version consistency check.

Verifies that the protocol version, Rust workspace version, and Python SDK
package version are all in sync. Exits non-zero with actionable errors on any
mismatch.

Protocol-affecting changes MUST update these together and trigger the Python
conformance gate (see .github/workflows/ci.yml).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

ERRORS = []


def fail(msg: str) -> None:
    ERRORS.append(msg)


# ── Cargo.toml (Rust workspace) ──────────────────────────────────────────


def read_rust_version() -> str:
    cargo = REPO_ROOT / "Cargo.toml"
    text = cargo.read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not m:
        fail("Cargo.toml: workspace package version not found")
        return "0.0.0"
    return m.group(1)


# ── Python SDK ───────────────────────────────────────────────────────────


def read_pyproject_version() -> str:
    pyproject = REPO_ROOT / "sdks" / "python" / "pyproject.toml"
    text = pyproject.read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not m:
        fail("sdks/python/pyproject.toml: project version not found")
        return "0.0.0"
    return m.group(1)


def read_sibna_version() -> str:
    init = REPO_ROOT / "sdks" / "python" / "sibna" / "__init__.py"
    text = init.read_text()
    m = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not m:
        fail("sdks/python/sibna/__init__.py: __version__ not found")
        return "0.0.0"
    return m.group(1)


# ── Protocol specification ───────────────────────────────────────────────


def read_protocol_wire_version() -> int:
    spec = REPO_ROOT / "PROTOCOL_SPECIFICATION.md"
    text = spec.read_text()
    # Spec §8: `| \`PROTOCOL_VERSION\` (wire) | 10 |`
    m = re.search(r"`PROTOCOL_VERSION`\s*\(wire\)\s*\|\s*(\d+)", text)
    if not m:
        fail("PROTOCOL_SPECIFICATION.md: PROTOCOL_VERSION (wire) not found")
        return -1
    return int(m.group(1))


def read_constants_wire_version() -> int:
    constants = REPO_ROOT / "sdks" / "python" / "sibna" / "constants.py"
    text = constants.read_text()
    m = re.search(r'^PROTOCOL_VERSION_WIRE\s*=\s*(\d+)\s*$', text, re.MULTILINE)
    if not m:
        fail("sdks/python/sibna/constants.py: PROTOCOL_VERSION_WIRE not found")
        return -1
    return int(m.group(1))


# ── CHANGELOG ────────────────────────────────────────────────────────────


def changelog_mentions(version: str) -> bool:
    changelog = REPO_ROOT / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8", errors="ignore")
    return f"v{version}" in text


def main() -> int:
    rust_ver = read_rust_version()
    py_ver = read_pyproject_version()
    init_ver = read_sibna_version()
    spec_wire = read_protocol_wire_version()
    const_wire = read_constants_wire_version()

    print(f"Rust workspace version   : {rust_ver}")
    print(f"Python package version   : {py_ver}")
    print(f"Python __version__       : {init_ver}")
    print(f"Spec wire version        : {spec_wire}")
    print(f"Python constants wire    : {const_wire}")

    # Package versions must all agree.
    if rust_ver != py_ver:
        fail(f"version mismatch: Rust {rust_ver} != Python package {py_ver}")
    if py_ver != init_ver:
        fail(f"version mismatch: Python package {py_ver} != __init__ {init_ver}")

    # Wire versions must agree.
    if spec_wire != const_wire:
        fail(
            f"wire version mismatch: spec {spec_wire} != Python constants {const_wire}"
        )

    # The changelog should reference the current version.
    if not changelog_mentions(rust_ver):
        fail(f"CHANGELOG.md does not reference current version {rust_ver}")

    if ERRORS:
        print("\nVERSION CONSISTENCY CHECK FAILED:")
        for e in ERRORS:
            print(f"  - {e}")
        return 1

    print("\nVersion consistency check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
