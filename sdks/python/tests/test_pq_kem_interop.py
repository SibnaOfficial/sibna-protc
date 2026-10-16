"""
Sibna Python SDK — ML-KEM-768 + hybrid X3DH cross-implementation tests.

These tests verify the post-quantum layer against the *retained Rust core* in
both directions, driving a test-only Rust example harness
(``core/examples/pq_kem_x3dh_interop.rs``) as a subprocess:

KEM
  - Rust encapsulates -> Python decapsulates
  - Python encapsulates -> Rust decapsulates

Hybrid X3DH handshake
  - Rust initiator -> Python responder (shared secrets match)
  - Python initiator -> Rust responder (shared secrets match)

No production randomness or security check is weakened: the Rust harness uses
the real fips203 ML-KEM-768 implementation and the real x3dh_responder_v3 /
x3dh_initiator_v3 code paths, and Python uses its real ml_kem_768_* and
x3dh_* implementations. Keys are freshly generated per test module run.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from sibna import (
    PreKeyBundle,
    X25519KeyPair,
    Ed25519KeyPair,
    Session,
)
from sibna.crypto import ml_kem_768_decapsulate, ml_kem_768_encapsulate, ml_kem_768_keypair
from sibna.x3dh import x3dh_initiator, x3dh_responder

CORE_DIR = Path(__file__).resolve().parents[3] / "core"

# Fixed X25519 seeds matching the Rust harness so both sides use the same
# long-term keys for the hybrid handshake cross-checks.
BOB_IDENTITY_SK = bytes([0x62] * 32)
BOB_SPK_SK = bytes([0x63] * 32)
ALICE_IDENTITY_SK = bytes([0x61] * 32)
ALICE_EPHEMERAL_SK = bytes([0x65] * 32)
DEVICE_ID = bytes(16)
TRANSCRIPT_EXT = bytes(32)


def _run_rust_example(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """Run the test-only Rust example harness with the given args."""
    cmd = ["cargo", "run", "--example", "pq_kem_x3dh_interop", *args]
    return subprocess.run(
        cmd,
        cwd=str(CORE_DIR),
        input=stdin,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _run_rust_decapsulate(sk_hex: str, ct_hex: str) -> str:
    """Run the Rust harness decapsulate subcommand; return shared secret hex."""
    proc = _run_rust_example("decapsulate", sk_hex, ct_hex)
    assert proc.returncode == 0, f"Rust decapsulate failed: {proc.stderr}"
    return proc.stdout.strip()


def _run_rust_x3dh_respond(payload: dict) -> str:
    """Run the Rust harness x3dh_respond subcommand; return shared secret hex."""
    proc = _run_rust_example("x3dh_respond", stdin=json.dumps(payload))
    assert proc.returncode == 0, f"Rust x3dh_respond failed: {proc.stderr}"
    return json.loads(proc.stdout)["shared_secret_hex"]


def _make_bob_bundle(pq_public_key_hex: str) -> PreKeyBundle:
    """Build Bob's prekey bundle with public keys matching the Rust generator's
    fixed X25519 seeds (bob identity = 0x62*32, bob SPK = 0x63*32)."""
    bob_ed = Ed25519KeyPair()
    bob_id_x = X25519KeyPair.from_seed(BOB_IDENTITY_SK)
    bob_spk_x = X25519KeyPair.from_seed(BOB_SPK_SK)
    spk = bob_spk_x.public_key
    return PreKeyBundle(
        identity_key=bob_ed.public_key,
        x25519_identity_key=bob_id_x.public_key,
        signed_prekey=spk,
        signed_prekey_signature=bob_ed.sign(b"SibnaSignedPreKey_v3" + spk),
        onetime_prekey=None,
        device_id=DEVICE_ID,
        pq_public_key=bytes.fromhex(pq_public_key_hex),
    )


@pytest.fixture(scope="module")
def vectors() -> dict:
    """Run the Rust harness in generate mode once and parse its JSON output."""
    proc = _run_rust_example("generate")
    assert proc.returncode == 0, f"Rust generate failed: {proc.stderr}"
    return json.loads(proc.stdout)


def test_ml_kem_768_key_sizes_match_fips203():
    """ML-KEM-768 key/ciphertext sizes match FIPS 203 (and the Rust fips203 crate)."""
    pk, sk = ml_kem_768_keypair()
    assert len(pk) == 1184, len(pk)
    assert len(sk) == 2400, len(sk)
    ct, ss = ml_kem_768_encapsulate(pk)
    assert len(ct) == 1088, len(ct)
    assert len(ss) == 32, len(ss)
    assert ml_kem_768_decapsulate(sk, ct) == ss


def test_kem_rust_encapsulates_python_decapsulates(vectors):
    """Rust -> Python: Rust encapsulates pk_a, Python decapsulates with sk_a."""
    ct = bytes.fromhex(vectors["ct_a_hex"])
    sk = bytes.fromhex(vectors["sk_a_hex"])
    expected_ss = bytes.fromhex(vectors["ss_a_hex"])
    ss = ml_kem_768_decapsulate(sk, ct)
    assert ss == expected_ss


def test_kem_python_encapsulates_rust_decapsulates(vectors):
    """Python -> Rust: Python encapsulates pk_b, Rust decapsulates with sk_b."""
    pk = bytes.fromhex(vectors["pk_b_hex"])
    ct_py, ss_py = ml_kem_768_encapsulate(pk)
    assert len(ct_py) == 1088
    assert len(ss_py) == 32
    ss_rust_hex = _run_rust_decapsulate(vectors["sk_b_hex"], ct_py.hex())
    assert bytes.fromhex(ss_rust_hex) == ss_py


def test_hybrid_x3dh_rust_initiator_python_responder(vectors):
    """Hybrid X3DH: Rust initiator -> Python responder shared secrets match."""
    bundle = _make_bob_bundle(vectors["pk_b_hex"])

    # Derive the responder-side shared secret at the primitive level.
    result = x3dh_responder(
        X25519KeyPair.from_seed(BOB_IDENTITY_SK),
        X25519KeyPair.from_seed(BOB_SPK_SK),
        None,
        bytes.fromhex(vectors["alice_identity_hex"]),
        bytes.fromhex(vectors["alice_ephemeral_hex"]),
        our_pq_secret_key=bytes.fromhex(vectors["sk_b_hex"]),
        peer_pq_ciphertext=bytes.fromhex(vectors["alice_pq_ct_to_b_hex"]),
        our_device_id=DEVICE_ID,
        peer_device_id=DEVICE_ID,
    )
    assert result.shared_secret == bytes.fromhex(vectors["alice_shared_secret_hex"])


def test_hybrid_x3dh_python_initiator_rust_responder(vectors):
    """Hybrid X3DH: Python initiator -> Rust responder shared secrets match."""
    bundle = _make_bob_bundle(vectors["pk_b_hex"])

    # Python initiates and encapsulates pk_b.
    alice_identity_x = X25519KeyPair.from_seed(ALICE_IDENTITY_SK)
    alice_ephemeral_x = X25519KeyPair.from_seed(ALICE_EPHEMERAL_SK)
    initiator_result = x3dh_initiator(
        alice_identity_x,
        alice_ephemeral_x,
        bundle,
        use_pq=True,
        our_device_id=DEVICE_ID,
        peer_device_id=DEVICE_ID,
    )
    assert initiator_result.pq_ciphertext is not None
    assert len(initiator_result.pq_ciphertext) == 1088

    # Rust responds to Python's encapsulation.
    payload = {
        "bob_identity_hex": BOB_IDENTITY_SK.hex(),
        "bob_spk_hex": BOB_SPK_SK.hex(),
        "alice_identity_pk_hex": vectors["alice_identity_hex"],
        "alice_ephemeral_pk_hex": vectors["alice_ephemeral_hex"],
        "our_pq_sk_hex": vectors["sk_b_hex"],
        "peer_pq_ct_hex": initiator_result.pq_ciphertext.hex(),
        "our_device_id_hex": DEVICE_ID.hex(),
        "peer_device_id_hex": DEVICE_ID.hex(),
        "transcript_ext_hex": TRANSCRIPT_EXT.hex(),
    }
    ss_rust_hex = _run_rust_x3dh_respond(payload)
    assert bytes.fromhex(ss_rust_hex) == initiator_result.shared_secret
