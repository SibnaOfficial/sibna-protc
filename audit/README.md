# Sibna Protocol v3.0.0 — Security Audit Deliverables

**Audit date:** June 2026
**Auditor:** Independent (opencode)
**Subject:** Sibna Core + Server v3.0.0
**Scope:** All Rust modules in `core/`, `server/`, `tests/`; thin SDK wrappers (C++, Go, Java, JS); build configuration.
**Out of scope:** Dart/Flutter/Python SDK reimplementations; side-channels; CI/CD; formal protocol verification.

## Final verdict
**NOT PRODUCTION-READY** — 4 CRITICAL + 7 HIGH + 4 MEDIUM findings identified; **all 15 patched in the working tree**. Core library test suite green (136/136, was 128/130 pre-patch). Project compiles from a clean checkout (was 16 build errors pre-patch). 12-vector attack integration test (`attack_tests::run_all_security_audits`) now passes with all 12 audits green (was 11/12 pre-patch). The remaining real bugs (SIBNA-2026-012, -014, -017, -018, -029, -030, -037, dependencies) should be remediated before production.

## How to read these deliverables

| File | Audience | Length | Read time |
|---|---|---:|---:|
| `EXECUTIVE_BRIEF.md` | Engineering leads, security officers, executives | 1 page | 5 min |
| `AUDIT_REPORT.md` | Engineering team, security team | 13 sections | 30 min |
| `FINDING_CATALOG.md` | Engineers fixing bugs, future auditors | 36 findings | 60 min |
| `VERIFICATION.md` | QA, CI maintainers | 1 page | 5 min |
| `PATCHES/*.md` | Engineers applying / reviewing patches | 18 files | 45 min |
| `BASELINE_TESTS.txt` | QA, regression-test baseline | 20 KB | reference |
| `FINAL_CORE_TESTS.txt` | QA, post-patch core lib tests | 21 KB | reference |
| `FINAL_ATTACK_TESTS.txt` | QA, post-patch attack integration tests | 6.6 KB | reference |

## Findings summary

| Severity | Count | Patched in tree |
|---|---:|:---:|
| CRITICAL | 4 | 4 |
| HIGH | 7 | 7 |
| MEDIUM | 9 | 4 (build fix, -013, -016, -020) |
| LOW | 6 | 0 |
| INFO | 5 | 0 |
| Dependency | 5 | 0 |
| **Total** | **36** | **15** |

## Top 4 CRITICAL findings (all patched)

1. **SIBNA-2026-001** — Cover traffic broken (empty plaintext rejected by `pad_message` and `CryptoHandler::encrypt`). Fix: allow empty plaintext in both layers. → `PATCHES/01` and `PATCHES/02`.
2. **SIBNA-2026-002** — Password KDF in non-`argon2` builds used HKDF-iterated (100k iterations of HKDF-SHA256, not password-grade). Fix: refuse to construct a password-protected context without `argon2` feature. → `PATCHES/03`.
3. **SIBNA-2026-003** — Server `Cargo.toml` did not enable `argon2` feature for `sibna-core`, so the **default production deployment** used the weak KDF. Fix: enable `argon2` in server. → `PATCHES/03`.
4. **SIBNA-2026-004** — Project did not compile on clean checkout (bincode 2.x migration half-done, two syntax errors, missing types). Fix: complete the migration. → `PATCHES/00`.

## Top 7 HIGH findings (all patched)

5. **SIBNA-2026-005** — Responder reused SPK as local ephemeral; loss of forward secrecy. → `PATCHES/08`.
6. **SIBNA-2026-006** — SPK signature payload mismatch (sign 32, verify 52). → `PATCHES/06`.
7. **SIBNA-2026-007** — Low-order X25519 public-key validation never invoked. → `PATCHES/06`, `PATCHES/07`.
8. **SIBNA-2026-008** — `OsRng` bypasses audited `SecureRandom` for X25519/Ed25519. → `PATCHES/05`, `PATCHES/14`.
9. **SIBNA-2026-009** — `ratchet::session::decrypt` cloned state and wrote back on failure. → `PATCHES/09`.
10. **SIBNA-2026-010** — `load_from_disk` zeroed `device_id`. → `PATCHES/04`.
11. **SIBNA-2026-011** — Storage manifest optional; deletion defeats rollback protection. → `PATCHES/10`, `PATCHES/11`.

## Outstanding work (before production)

1. Fix the 4-5 integration test failures documented in `VERIFICATION.md` § "Outstanding integration test failures". These are real bugs (SIBNA-2026-013, -014, -020).
2. Address the 9 MEDIUM findings (SIBNA-2026-012, -013, -014, -016, -017, -018, -020, -029, -030).
3. Address the 4 remaining dependency findings:
   - **SIBNA-2026-032 — `fips203`**: the **pinned** version in `Cargo.toml:53` is **`0.4.3`** (per `VERIFICATION.md:152` and `FINDING_CATALOG.md:824-830`). The `0.5.0` reference in `AUDIT_REPORT.md:168,273` is a *target* upgrade that was never applied. The status of `0.4.3` against the final FIPS 203 standard (released August 2024) is unverified; the upgrade should be re-evaluated before any release.
   - **SIBNA-2026-034** — `axum` minor-version spread — **RESOLVED** (unified at v0.7.9).
   - **SIBNA-2026-035** — `zmij 1.0.21` is a legitimate dtolnay crate (false positive) — **RESOLVED**.
   - **SIBNA-2026-036** — `Cargo.lock` not vendored — N/A (correctly gitignored for library crates via `**/Cargo.lock`).
   - ~~SIBNA-2026-033 (sled)~~ — **RESOLVED** (replaced with `redb`).
4. Run `cargo audit` and `cargo deny` as a pre-merge requirement.
5. Conduct a follow-up audit focused on the P2P module and the FFI surface (current audit was line-by-line on the lower layers; P2P and FFI were reviewed at a higher level).

## Verification commands

```bash
# Build (clean checkout, post-patch)
cargo check --workspace          # 0 errors, 8 warnings (all unused_*)

# Core lib unit tests (post-patch)
cargo test --lib -p sibna-core   # 136/136 pass

# 12-vector attack integration test (post-patch)
cargo test -p sibna-tests --test attack_tests run_all_security_audits
                              # all 12 audits pass

# Multi-device tests (post-patch)
cargo test -p sibna-tests --test multi_device_tests
                              # 3/3 pass
```
