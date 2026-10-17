#!/usr/bin/env bash
# .SYNOPSIS
#   Unified Rust <-> Python Double Ratchet interoperability test runner.
# .DESCRIPTION
#   Executes the full cross-implementation workflow in order:
#     1. Clean up any stale temporary fixtures.
#     2. Python generates fresh Double Ratchet ciphertext fixtures.
#     3. Rust decrypts & verifies Python ciphertexts, writes Rust ciphertext fixtures.
#     4. Rust negative tests: tampered ciphertext and incorrect associated data.
#     5. Python decrypts & verifies Rust ciphertexts.
#   All subprocess failures propagate as a nonzero exit code.
# .EXAMPLE
#   bash run_interop.sh

set -euo pipefail

# Dedicated temporary fixture paths (matches Python tempfile.gettempdir() and
# Rust std::env::temp_dir() on all platforms)
PY_CT_PATH="${TEMPDIR:-/tmp}/sibna_py_ratchet_ct.json"
RUST_CT_PATH="${TEMPDIR:-/tmp}/sibna_rust_ratchet_ct.json"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SDK_DIR="${REPO_ROOT}/sdks/python"
CORE_DIR="${REPO_ROOT}/core"

echo "=== SIBNA Rust <-> Python Double Ratchet Interop Runner ==="
echo "Python fixture path: ${PY_CT_PATH}"
echo "Rust fixture path:   ${RUST_CT_PATH}"

# ---- Step 0: Clean up stale fixtures ---------------------------------------
echo ""
echo "[0/5] Cleaning up stale temporary fixtures..."
rm -f "${PY_CT_PATH}" "${RUST_CT_PATH}"

# ---- Step 1: Python generates fresh ciphertexts ----------------------------
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

# ---- Step 4: Python decrypts Rust ciphertexts ------------------------------
echo ""
echo "[3/5] Python: decrypting Rust-generated ciphertexts..."
(
    cd "${PY_SDK_DIR}"
    python -m pytest tests/test_ratchet_python_to_rust_interop.py::test_python_decrypts_rust_generated_ciphertexts -m interop -v
)
echo "OK: Python decrypted Rust ciphertexts."

# ---- Step 5: Cleanup -------------------------------------------------------
echo ""
echo "[4/5] Cleaning up temporary fixtures..."
rm -f "${PY_CT_PATH}" "${RUST_CT_PATH}"

echo ""
echo "=== ALL INTEROP TESTS PASSED ==="
exit 0
