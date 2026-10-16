"""
Sibna Python SDK — encrypted storage conformance tests.

Covers save/load roundtrip, manifest integrity, tamper rejection, and
rollback (sequence-number) protection.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from sibna.errors import StorageError
from sibna.storage import SecureStorage


def _make_storage():
    return SecureStorage(os.urandom(32))


def test_storage_save_load_roundtrip():
    store = _make_storage()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "store.bin")
        salt = store.save(path, {"sessions": {}, "groups": {}}, sequence_number=1)
        payload, salt2 = store.load(path)
        assert payload["version"] == 1
        assert payload["sequence_number"] == 1
        assert salt2 == salt


def test_storage_manifest_tamper_rejected():
    store = _make_storage()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "store.bin")
        store.save(path, {"sessions": {}, "groups": {}}, sequence_number=1)
        # Corrupt the manifest MAC.
        with open(path + ".manifest", "r+") as f:
            import json

            m = json.load(f)
            m["manifest_mac"] = "00" * 32
            f.seek(0)
            json.dump(m, f)
            f.truncate()
        with pytest.raises(StorageError):
            store.load(path)


def test_storage_blob_tamper_rejected():
    store = _make_storage()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "store.bin")
        store.save(path, {"sessions": {}, "groups": {}}, sequence_number=1)
        with open(path, "r+b") as f:
            f.seek(40)
            f.write(b"\xff")
        with pytest.raises(StorageError):
            store.load(path)


def test_storage_rollback_rejected():
    store = _make_storage()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "store.bin")
        store.save(path, {"sessions": {}, "groups": {}}, sequence_number=1)
        # Tamper the manifest to claim a higher sequence number than the blob.
        import json

        with open(path + ".manifest", "r+") as f:
            m = json.load(f)
            m["sequence_number"] = 999
            f.seek(0)
            json.dump(m, f)
            f.truncate()
        with pytest.raises(StorageError):
            store.load(path)
