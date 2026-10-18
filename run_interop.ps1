#!/usr/bin/env powershell
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
#   - Python tests write/read  $env:TEMP/sibna_py_ratchet_ct.json
#   - Rust   tests write/read  $env:TEMP/sibna_rust_ratchet_ct.json
#   which is the same OS temp dir used by Python's tempfile.gettempdir() and
#   Rust's std::env::temp_dir() on Windows.
# .EXAMPLE
#   powershell -ExecutionPolicy Bypass -File run_interop.ps1

$ErrorActionPreference = "Stop"

# Derive the repo root from this script's location (works on any checkout path).
# run_interop.ps1 lives at the repo root, so its directory IS the repo root.
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
$REPO_ROOT = Resolve-Path $SCRIPT_DIR
$PY_SDK_DIR = Join-Path $REPO_ROOT "sdks\python"
$CORE_DIR = Join-Path $REPO_ROOT "core"

# Consistent temporary fixture location shared by Python, Rust, and this runner.
$TMP = $env:TEMP
if (-not $TMP) { $TMP = [System.IO.Path]::GetTempPath() }
$PY_CT_PATH = Join-Path $TMP "sibna_py_ratchet_ct.json"
$RUST_CT_PATH = Join-Path $TMP "sibna_rust_ratchet_ct.json"

Write-Host "=== SIBNA Rust <-> Python Double Ratchet Interop Runner ===" -ForegroundColor Cyan
Write-Host "Temp dir:          $TMP" -ForegroundColor Cyan
Write-Host "Python fixture:    $PY_CT_PATH" -ForegroundColor Cyan
Write-Host "Rust fixture:      $RUST_CT_PATH" -ForegroundColor Cyan
Write-Host "Repo root:         $REPO_ROOT" -ForegroundColor Cyan

# Safe cleanup of the fixtures we own (success or failure).
function Cleanup-Fixtures {
    Remove-Item -Path $PY_CT_PATH -ErrorAction SilentlyContinue
    Remove-Item -Path $RUST_CT_PATH -ErrorAction SilentlyContinue
}

# ---- Step 0: Clean up stale fixtures ---------------------------------------
Write-Host "`n[0/5] Cleaning up stale temporary fixtures..." -ForegroundColor Yellow
Cleanup-Fixtures

$exitCode = 0
try {
    # ---- Step 1: Python generates fresh ciphertexts (Python -> Rust) -------
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

    # ---- Step 2 & 3: Rust decrypts Python ciphertexts, writes Rust ct ------
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

    # ---- Step 4: Python decrypts Rust ciphertexts (Rust -> Python) ---------
    Write-Host "`n[3/5] Python: decrypting Rust-generated ciphertexts..." -ForegroundColor Yellow
    Set-Location $PY_SDK_DIR
    & python -m pytest tests/test_ratchet_python_to_rust_interop.py::test_python_decrypts_rust_generated_ciphertexts -m interop -v
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: Python Rust-ciphertext decryption exited with code $LASTEXITCODE" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "OK: Python decrypted Rust ciphertexts." -ForegroundColor Green

    Write-Host "`n=== ALL INTEROP TESTS PASSED ===" -ForegroundColor Green
    exit 0
}
catch {
    Write-Host "FAIL: Interop runner aborted: $_" -ForegroundColor Red
    $exitCode = 1
}
finally {
    # ---- Step 5: Cleanup ---------------------------------------------------
    Write-Host "`n[4/5] Cleaning up temporary fixtures..." -ForegroundColor Yellow
    Cleanup-Fixtures
}

exit $exitCode
