#!/usr/bin/env bash
# .SYNOPSIS
#   Unified Rust <-> Python Double Ratchet interoperability test runner.
# .DESCRIPTION
#   Executes the full cross-implementation workflow in order:
#     1. Python generates fresh Double Ratchet ciphertext fixtures (Python -> Rust).
#     2. Rust decrypts & verifies Python ciphertexts, writes Rust ciphertext fixtures
#        (Rust -> Python), and runs negative tests.
#     3. Python decrypts & verifies Rust-generated ciphertexts.
#   All subprocess failures propagate as a nonzero exit code.
#
# PATH CONTRACT (must match the test participants):
#   - Python tests write/read  ${TMP}/sibna_py_ratchet_ct.json
#   - Rust   tests write/read  ${TMP}/sibna_rust_ratchet_ct.json
#   where ${TMP} = ${TMPDIR:-/tmp} (POSIX) — the same OS temp dir used by
#   Python's tempfile.gettempdir() and Rust's std::env::temp_dir().
# .EXAMPLE
#   bash run_interop.sh

set -euo pipefail

# Consistent temporary fixture location shared by Python, Rust, and this runner.
TMP="${TMPDIR:-/tmp}"
PY_CT_PATH="${TMP}/sibna_py_ratchet_ct.json"
RUST_CT_PATH="${TMP}/sibna_rust_ratchet_ct.json"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SDK_DIR="${REPO_ROOT}/sdks/python"
CORE_DIR="${REPO_ROOT}/core"

# Safe cleanup on exit (success or failure). Removes only the interop fixtures
# we own, never the caller's broader temp directory.
cleanup() {
    rm -f "${PY_CT_PATH}" "${RUST_CT_PATH}"
}
trap cleanup EXIT

echo "=== SIBNA Rust <-> Python Double Ratchet Interop Runner ==="
echo "Temp dir:          ${TMP}"
echo "Python fixture:    ${PY_CT_PATH}"
echo "Rust fixture:      ${RUST_CT_PATH}"
echo "Repo root:         ${REPO_ROOT}"

# ---- Step 0: Clean up stale fixtures ---------------------------------------
echo ""
echo "[0/5] Cleaning up stale temporary fixtures..."
cleanup

# ---- Step 1: Python generates fresh ciphertexts (Python -> Rust) -----------
echo ""
echo "[1/5] Python: generating ciphertexts for Rust..."
(
    cd "${PY_SDK_DIR}"
    python -m pytest tests/test_ratchet_python_to_rust_interop.py::test_python_encrypt_writes_ciphertexts_for_rust -m interop -v
)
if [ ! -f "${PY_CT_PATH}" ]; then
    echo "FAIL: Python did not write fixture at ${PY_CT_PATH}" >&2
    exit 1
fi
echo "OK: Python ciphertext fixture written."

# ---- Step 2 & 3: Rust decrypts Python ciphertexts, writes Rust ciphertexts --
echo ""
echo "[2/5] Rust: decrypting Python ciphertexts + running negative tests..."
(
    cd "${CORE_DIR}"
    cargo test --test test_python_interop
)
if [ ! -f "${RUST_CT_PATH}" ]; then
    echo "FAIL: Rust did not write fixture at ${RUST_CT_PATH}" >&2
    exit 1
fi
echo "OK: Rust ciphertext fixture written."

# ---- Step 4: Python decrypts Rust ciphertexts (Rust -> Python) -------------
echo ""
echo "[3/5] Python: decrypting Rust-generated ciphertexts..."
(
    cd "${PY_SDK_DIR}"
    python -m pytest tests/test_ratchet_python_to_rust_interop.py::test_python_decrypts_rust_generated_ciphertexts -m interop -v
)
echo "OK: Python decrypted Rust ciphertexts."

echo ""
echo "=== ALL INTEROP TESTS PASSED ==="
exit 0
