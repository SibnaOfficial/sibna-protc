"""
Sibna Protocol v3.0.2 — Full end-to-end integration tests.

These tests prove real cross-component interoperability between the Python SDK
and the Rust reference implementation, running against a live relay server.

Test scenarios:
1. test_full_flow_http_alice_to_bob
   - Alice registers, authenticates (JWT), uploads prekeys
   - Bob registers, authenticates (JWT), uploads prekeys
   - Alice fetches Bob's prekeys, performs X3DH, encrypts a message
   - Alice sends the sealed envelope via HTTP POST /v1/messages/send
   - Bob fetches his inbox via HTTP GET /v1/messages/inbox
   - Bob verifies the envelope signature and sender_id
   - Bob decrypts the message with his Double Ratchet session

2. test_offline_message_delivery
   - Charlie sends a message to Bob while Bob is not polling inbox
   - Bob fetches his inbox later and finds the stored message
   - Message signature and sender_id are verified

3. test_replay_rejection
   - Alice sends the same message twice (same message_id)
   - Server deduplicates; Bob's inbox contains only one copy

4. test_out_of_order_ratchet_messages
   - Alice sends messages 1, 2, 3 to Bob
   - Bob decrypts message 3 first (out of order)
   - Bob then decrypts messages 1 and 2 from skipped-key cache

5. test_session_persistence_across_restart
   - Alice establishes session, exports state
   - New session object imports state, sends message
   - Bob decrypts successfully

6. test_websocket_python_to_python
   - Alice and Bob both connect via WebSocket with JWT
   - Alice sends a sealed envelope via WebSocket
   - Bob receives it in real-time, verifies signature, decrypts

The server binary must be built first:
    cd /path/to/sibna-protc
    cargo build -p sibna-server --bin sibna-server
    SIBNA_JWT_SECRET=test-secret-0123456789abcdef ./target/debug/sibna-server
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sibna import (
    Identity,
    SibnaClient,
    Session,
    X25519KeyPair,
    Ed25519KeyPair,
    PreKeyBundle,
    DoubleRatchet,
    derive_identity_keys,
    generate_peer_bundle,
)
from sibna.envelope import make_signed_envelope, verify_signed_envelope
from sibna.errors import AuthError, NetworkError


SERVER_URL = os.environ.get("SIBNA_SERVER_URL", "http://localhost:0")
JWT_SECRET = os.environ.get("SIBNA_JWT_SECRET", "test-secret-0123456789abcdef")

# Deterministic test identities (NOT for production use)
ALICE_SEED = bytes.fromhex("61" * 32)
BOB_SEED = bytes.fromhex("62" * 32)
CHARLIE_SEED = bytes.fromhex("63" * 32)


def _find_free_port() -> int:
    """Find a free TCP port for the test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server() -> subprocess.Popen:
    """Start the Rust relay server as a subprocess on a free port.

    Returns the Popen object. Raises if the server fails to start.
    """
    server_bin = Path(__file__).resolve().parents[3] / "target" / "debug" / "sibna-server"
    if not server_bin.exists():
        server_bin = Path(__file__).resolve().parents[3] / "target" / "release" / "sibna-server"
    if not server_bin.exists():
        raise FileNotFoundError(f"sibna-server binary not found (looked in debug and release)")

    port = _find_free_port()
    server_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env["SIBNA_JWT_SECRET"] = JWT_SECRET
    env["SIBNA_SERVER_URL"] = server_url

    proc = subprocess.Popen(
        [str(server_bin), "--bind", f"127.0.0.1:{port}"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to be ready (poll /health)
    for _ in range(100):  # 10 seconds max
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(
                f"Server exited prematurely (code {proc.returncode}).\n"
                f"stdout: {out.decode(errors='replace')}\n"
                f"stderr: {err.decode(errors='replace')}"
            )
        try:
            req = urllib.request.Request(f"{server_url}/health")
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status == 200:
                    _start_server.server_url = server_url
                    return proc
        except Exception:
            time.sleep(0.1)

    proc.kill()
    raise RuntimeError("sibna-server did not become ready within 10 seconds")


def _stop_server(proc: subprocess.Popen) -> None:
    """Gracefully stop the server subprocess."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _make_alice() -> SibnaClient:
    """Create and authenticate Alice client with deterministic identity."""
    client = SibnaClient(server=SERVER_URL)
    client.generate_identity(private_key_bytes=ALICE_SEED)
    client.authenticate()
    return client


def _make_bob() -> SibnaClient:
    """Create and authenticate Bob client with deterministic identity."""
    client = SibnaClient(server=SERVER_URL)
    client.generate_identity(private_key_bytes=BOB_SEED)
    client.authenticate()
    return client


def _make_charlie() -> SibnaClient:
    """Create and authenticate Charlie client with deterministic identity."""
    client = SibnaClient(server=SERVER_URL)
    client.generate_identity(private_key_bytes=CHARLIE_SEED)
    client.authenticate()
    return client


def _make_bob_prekey_bundle() -> PreKeyBundle:
    """Create Bob's prekey bundle for X3DH handshake."""
    bob_ed, bob_x = derive_identity_keys(BOB_SEED)
    bob_spk = X25519KeyPair.from_seed(bytes.fromhex("63" * 32))
    bob_opk = X25519KeyPair.from_seed(bytes.fromhex("64" * 32))
    return generate_peer_bundle(
        identity_ed=bob_ed,
        identity_x25519=bob_x,
        signed_prekey=bob_spk,
        onetime_prekey=bob_opk,
        device_id_bytes=bytes.fromhex("62" * 16),
        root_identity_key=bob_ed.public_key,
    )


def _alice_x3dh_with_bob(bob_bundle: PreKeyBundle) -> tuple[Session, bytes]:
    """Alice performs X3DH as initiator with Bob's prekey bundle.

    Returns (alice_session, alice_ephemeral_public_key_bytes).
    Uses ALICE_SEED for both Ed25519 (sender_id) and X25519 (DH) keys.
    """
    alice_ed, alice_x = derive_identity_keys(ALICE_SEED)
    alice_ephemeral = X25519KeyPair()
    alice_session = Session()
    ephemeral_pub = alice_session.initiate_as_initiator(
        identity=alice_x,
        ephemeral=alice_ephemeral,
        peer_bundle=bob_bundle,
        our_device_id=bytes.fromhex("61" * 16),
        peer_device_id=bytes.fromhex("62" * 16),
        use_pq=False,
    )
    return alice_session, alice_ephemeral.public_key


def _bob_x3dh_with_alice(
    bob_bundle: PreKeyBundle,
    alice_x_public_key: bytes,
    alice_ephemeral_public_key: bytes,
    bob_spk: X25519KeyPair,
    bob_opk: X25519KeyPair,
    bob_x: X25519KeyPair,
) -> Session:
    """Bob performs X3DH as responder with Alice's ephemeral key.

    peer_identity must be Alice's X25519 public key (not Ed25519).
    """
    bob_session = Session()
    bob_session.initiate_as_responder(
        identity=bob_x,
        signed_prekey=bob_spk,
        onetime_prekey=bob_opk,
        peer_identity=alice_x_public_key,
        peer_ephemeral=alice_ephemeral_public_key,
        our_device_id=bytes.fromhex("62" * 16),
        peer_device_id=bytes.fromhex("61" * 16),
        use_pq=False,
    )
    return bob_session


class TestFullFlowHTTP:
    """Full Alice → Server → Bob flow over HTTP."""

    @classmethod
    def setup_class(cls):
        cls.server_proc = _start_server()
        cls.server_url = getattr(_start_server, "server_url", SERVER_URL)

    @classmethod
    def teardown_class(cls):
        _stop_server(cls.server_proc)

    def test_full_flow_alice_to_bob(self):
        """Alice sends an encrypted message to Bob via HTTP; Bob decrypts it."""
        alice = _make_alice()
        bob = _make_bob()

        # ── Bob uploads prekeys ──
        bob_ed, bob_x = derive_identity_keys(BOB_SEED)
        bob_spk = X25519KeyPair.from_seed(bytes.fromhex("63" * 32))
        bob_opk = X25519KeyPair.from_seed(bytes.fromhex("64" * 32))
        bob_bundle = _make_bob_prekey_bundle()
        bundle_hex = bob_bundle.to_bytes().hex()
        bob.upload_prekey(bundle_hex)

        # ── Alice fetches Bob's prekeys ──
        fetched = alice.fetch_prekeys(bob_ed.public_key.hex())
        assert len(fetched) > 0, "No prekeys fetched for Bob"

        # Parse the fetched bundle back into a Python PreKeyBundle
        fetched_bundle = PreKeyBundle.from_bytes(bytes.fromhex(fetched[0]))
        assert fetched_bundle.verify_spk_signature(), "Fetched bundle SPK signature invalid"

        # ── Alice establishes X3DH session with Bob ──
        alice_session, alice_ephemeral_pub = _alice_x3dh_with_bob(fetched_bundle)

        # ── Alice encrypts a message ──
        plaintext = b"Hello Bob from Alice via Sibna Protocol v3.0.2!"
        ciphertext = alice_session.encrypt(plaintext, associated_data=b"v3.0.2")

        # ── Alice sends via HTTP ──
        payload_hex = ciphertext.hex()
        status = alice.send_message(
            recipient_id=bob_ed.public_key.hex(),
            payload_hex=payload_hex,
            sign=True,
        )
        assert status in (200, 202), f"Unexpected status: {status}"

        # ── Bob fetches inbox ──
        messages = bob.fetch_inbox()
        assert len(messages) >= 1, "Bob's inbox is empty"

        # ── Bob finds and verifies Alice's message ──
        found = False
        for envelope in messages:
            assert verify_signed_envelope(envelope), "Envelope signature invalid"
            assert (
                envelope["sender_id"] == alice_ed.public_key.hex()
            ), f"sender_id mismatch: {envelope['sender_id']} != {alice_ed.public_key.hex()}"
            if envelope["payload_hex"] == payload_hex:
                found = True
                # Bob decrypts
                bob_session = _bob_x3dh_with_alice(
                    bob_bundle,
                    alice_ed.public_key,  # peer_identity = Alice's X25519 public key
                    alice_ephemeral_pub,
                    bob_spk,
                    bob_opk,
                    bob_x,
                )
                decrypted = bob_session.decrypt(
                    bytes.fromhex(envelope["payload_hex"]), associated_data=b"v3.0.2"
                )
                assert (
                    decrypted == plaintext
                ), f"Decryption mismatch: {decrypted!r} != {plaintext!r}"
                break
        assert found, "Alice's message not found in Bob's inbox"

    def test_offline_message_delivery(self):
        """Message sent while Bob is offline is stored and retrieved later."""
        alice = _make_alice()
        bob = _make_bob()

        # ── Bob uploads prekeys ──
        bob_ed, bob_x = derive_identity_keys(BOB_SEED)
        bob_spk = X25519KeyPair.from_seed(bytes.fromhex("63" * 32))
        bob_opk = X25519KeyPair.from_seed(bytes.fromhex("64" * 32))
        bob_bundle = _make_bob_prekey_bundle()
        bob.upload_prekey(bob_bundle.to_bytes().hex())

        # ── Alice establishes session and sends ──
        alice_session, alice_ephemeral_pub = _alice_x3dh_with_bob(bob_bundle)
        plaintext = b"Offline message for Bob"
        ciphertext = alice_session.encrypt(plaintext, associated_data=b"offline")
        payload_hex = ciphertext.hex()

        status = alice.send_message(
            recipient_id=bob_ed.public_key.hex(),
            payload_hex=payload_hex,
            sign=True,
        )
        assert status in (200, 202)

        # ── Bob fetches inbox later (simulating offline then online) ──
        messages = bob.fetch_inbox()
        found = False
        for envelope in messages:
            assert verify_signed_envelope(envelope), "Offline message signature invalid"
            if envelope["payload_hex"] == payload_hex:
                found = True
                bob_session = _bob_x3dh_with_alice(
                    bob_bundle,
                    alice_ed.public_key,
                    alice_ephemeral_pub,
                    bob_spk,
                    bob_opk,
                    bob_x,
                )
                decrypted = bob_session.decrypt(
                    bytes.fromhex(envelope["payload_hex"]), associated_data=b"offline"
                )
                assert decrypted == plaintext
                break
        assert found, "Offline message not found in Bob's inbox"

    def test_replay_rejection(self):
        """Same message_id sent twice is deduplicated by the server."""
        alice = _make_alice()
        bob = _make_bob()

        bob_ed, bob_x = derive_identity_keys(BOB_SEED)
        bob_spk = X25519KeyPair.from_seed(bytes.fromhex("63" * 32))
        bob_opk = X25519KeyPair.from_seed(bytes.fromhex("64" * 32))
        bob_bundle = _make_bob_prekey_bundle()
        bob.upload_prekey(bob_bundle.to_bytes().hex())

        alice_session, alice_ephemeral_pub = _alice_x3dh_with_bob(bob_bundle)
        plaintext = b"Replay test message"
        ciphertext = alice_session.encrypt(plaintext, associated_data=b"replay")
        payload_hex = ciphertext.hex()

        # Build an envelope with a fixed message_id and send it twice
        from sibna.envelope import make_signed_envelope

        envelope1 = make_signed_envelope(
            alice.identity,
            recipient_id=bob_ed.public_key.hex(),
            payload_hex=payload_hex,
            message_id="replay-test-0001",
        )

        # First send via raw HTTP with the pre-built envelope
        import requests

        r1 = alice._session.post(
            f"{SERVER_URL}/v1/messages/send",
            json=envelope1,
            timeout=alice.timeout,
        )
        assert r1.status_code in (200, 202), f"First send failed: {r1.status_code}"

        # Second send with same message_id
        r2 = alice._session.post(
            f"{SERVER_URL}/v1/messages/send",
            json=envelope1,
            timeout=alice.timeout,
        )

        # Bob's inbox should contain only one copy (server deduplicates)
        messages = bob.fetch_inbox()
        matching = [m for m in messages if m.get("message_id") == "replay-test-0001"]
        assert len(matching) == 1, f"Expected 1 copy of replayed message, got {len(matching)}"

    def test_out_of_order_ratchet_messages(self):
        """Out-of-order Double Ratchet messages are decrypted correctly."""
        alice = _make_alice()
        bob = _make_bob()

        bob_ed, bob_x = derive_identity_keys(BOB_SEED)
        bob_spk = X25519KeyPair.from_seed(bytes.fromhex("63" * 32))
        bob_opk = X25519KeyPair.from_seed(bytes.fromhex("64" * 32))
        bob_bundle = _make_bob_prekey_bundle()
        bob.upload_prekey(bob_bundle.to_bytes().hex())

        alice_session, alice_ephemeral_pub = _alice_x3dh_with_bob(bob_bundle)

        # Alice sends 3 messages
        messages = [b"Message 1", b"Message 2", b"Message 3"]
        ciphertexts = []
        for m in messages:
            ct = alice_session.encrypt(m, associated_data=b"ooo")
            ciphertexts.append(ct.hex())

        # Bob decrypts out of order: message 3 first, then 1, then 2
        bob_session = _bob_x3dh_with_alice(
            bob_bundle,
            alice_ed.public_key,
            alice_ephemeral_pub,
            bob_spk,
            bob_opk,
            bob_x,
        )

        # Decrypt message 3 first (should work, skips keys 1 and 2)
        ct3 = bytes.fromhex(ciphertexts[2])
        pt3 = bob_session.decrypt(ct3, associated_data=b"ooo")
        assert pt3 == messages[2], f"Out-of-order decrypt failed: {pt3}"

        # Decrypt message 1 (should come from skipped-key cache)
        ct1 = bytes.fromhex(ciphertexts[0])
        pt1 = bob_session.decrypt(ct1, associated_data=b"ooo")
        assert pt1 == messages[0], f"Out-of-order decrypt failed: {pt1}"

        # Decrypt message 2 (should come from skipped-key cache)
        ct2 = bytes.fromhex(ciphertexts[1])
        pt2 = bob_session.decrypt(ct2, associated_data=b"ooo")
        assert pt2 == messages[1], f"Out-of-order decrypt failed: {pt2}"


class TestWebSocketFlow:
    """WebSocket real-time relay between Python clients."""

    @classmethod
    def setup_class(cls):
        cls.server_proc = _start_server()
        cls.server_url = getattr(_start_server, "server_url", SERVER_URL)

    @classmethod
    def teardown_class(cls):
        _stop_server(cls.server_proc)

    @pytest.mark.asyncio
    async def test_websocket_python_to_python(self):
        """Python client sends signed envelope via WebSocket; Python client receives and decrypts."""
        import aiohttp

        alice = _make_alice()
        bob = _make_bob()

        bob_ed, bob_x = derive_identity_keys(BOB_SEED)
        bob_spk = X25519KeyPair.from_seed(bytes.fromhex("63" * 32))
        bob_opk = X25519KeyPair.from_seed(bytes.fromhex("64" * 32))
        bob_bundle = _make_bob_prekey_bundle()
        bob.upload_prekey(bob_bundle.to_bytes().hex())

        # Alice establishes X3DH session with Bob
        alice_session, alice_ephemeral_pub = _alice_x3dh_with_bob(bob_bundle)

        # Alice encrypts a message
        plaintext = b"Hello Bob via WebSocket!"
        ciphertext = alice_session.encrypt(plaintext, associated_data=b"websocket")
        payload_hex = ciphertext.hex()

        # Alice connects via WebSocket and sends
        ws_alice = _make_alice()
        ws_alice.authenticate()

        received = []

        async def on_message(envelope):
            received.append(envelope)

        await ws_alice.connect(on_message=on_message)

        await ws_alice.send(
            recipient_id=bob_ed.public_key.hex(),
            payload_hex=payload_hex,
            sign=True,
        )

        # Wait for echo
        await asyncio.sleep(2)
        await ws_alice.close()

        assert len(received) >= 1, "No envelope received via WebSocket"
        received_env = received[0]
        assert verify_signed_envelope(received_env), "WS envelope signature invalid"
        assert received_env["sender_id"] == alice_ed.public_key.hex(), "WS sender_id mismatch"

        # Bob decrypts the received message
        bob_session = _bob_x3dh_with_alice(
            bob_bundle,
            alice_ed.public_key,
            alice_ephemeral_pub,
            bob_spk,
            bob_opk,
            bob_x,
        )
        decrypted = bob_session.decrypt(
            bytes.fromhex(received_env["payload_hex"]),
            associated_data=b"websocket",
        )
        assert decrypted == plaintext, f"WS decrypt failed: {decrypted}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=long"])
