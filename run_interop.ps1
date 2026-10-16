#!/usr/bin/env powershell
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
#   powershell -ExecutionPolicy Bypass -File run_interop.ps1

$ErrorActionPreference = "Stop"

# Dedicated temporary fixture paths
$PY_CT_PATH = Join-Path $env:TEMP "sibna_py_ratchet_ct.json"
$RUST_CT_PATH = Join-Path $env:TEMP "sibna_rust_ratchet_ct.json"

$REPO_ROOT = $PSScriptRoot
$PY_SDK_DIR = Join-Path $REPO_ROOT "sdks\python"
$CORE_DIR = Join-Path $REPO_ROOT "core"

Write-Host "=== SIBNA Rust <-> Python Double Ratchet Interop Runner ===" -ForegroundColor Cyan
Write-Host "Python fixture path: $PY_CT_PATH" -ForegroundColor Cyan
Write-Host "Rust fixture path:   $RUST_CT_PATH" -ForegroundColor Cyan

# ---- Step 0: Clean up stale fixtures ---------------------------------------
Write-Host "`n[0/5] Cleaning up stale temporary fixtures..." -ForegroundColor Yellow
Remove-Item -Path $PY_CT_PATH -ErrorAction SilentlyContinue
Remove-Item -Path $RUST_CT_PATH -ErrorAction SilentlyContinue

# ---- Step 1: Python generates fresh ciphertexts ----------------------------
Write-Host "`n[1/5] Python: generating ciphertexts for Rust..." -ForegroundColor Yellow
Set-Location $PY_SDK_DIR
& python -m pytest tests/test_ratchet_python_to_rust_interop.py::test_python_encrypt_writes_ciphertexts_for_rust -m interop -v
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: Python ciphertext generation exited with code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
if (-not (Test-Path $PY_CT_PATH)) {
    Write-Host "FAIL: Python did not write fixture at $PY_CT_PATH" -ForegroundColor Red
    exit 1
}
Write-Host "OK: Python ciphertext fixture written." -ForegroundColor Green

# ---- Step 2 & 3: Rust decrypts Python ciphertexts, writes Rust ciphertexts --
Write-Host "`n[2/5] Rust: decrypting Python ciphertexts + running negative tests..." -ForegroundColor Yellow
Set-Location $CORE_DIR
& cargo test --test test_python_interop
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: Rust interop tests exited with code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
if (-not (Test-Path $RUST_CT_PATH)) {
    Write-Host "FAIL: Rust did not write fixture at $RUST_CT_PATH" -ForegroundColor Red
    exit 1
}
Write-Host "OK: Rust ciphertext fixture written." -ForegroundColor Green

# ---- Step 4: Python decrypts Rust ciphertexts ------------------------------
Write-Host "`n[3/5] Python: decrypting Rust-generated ciphertexts..." -ForegroundColor Yellow
Set-Location $PY_SDK_DIR
& python -m pytest tests/test_ratchet_python_to_rust_interop.py::test_python_decrypts_rust_generated_ciphertexts -m interop -v
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: Python Rust-ciphertext decryption exited with code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "OK: Python decrypted Rust ciphertexts." -ForegroundColor Green

# ---- Step 5: Cleanup -------------------------------------------------------
Write-Host "`n[4/5] Cleaning up temporary fixtures..." -ForegroundColor Yellow
Remove-Item -Path $PY_CT_PATH -ErrorAction SilentlyContinue
Remove-Item -Path $RUST_CT_PATH -ErrorAction SilentlyContinue

Write-Host "`n=== ALL INTEROP TESTS PASSED ===" -ForegroundColor Green
exit 0
