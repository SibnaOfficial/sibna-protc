# Contributing to Sibna Protocol

## Security First

Sibna is a high-assurance cryptographic library. All contributions must adhere to these strict security invariants.

### Critical Rules

- **No `.unwrap()` or `.expect()` in Production Code** — Use `?` operator or explicit matching for error handling.
- **No New Dependencies** — Any addition must be vetted. Run `cargo audit` before suggesting a new crate.
- **No Custom Cryptographic Primitives** — Use only audited crates from the `RustCrypto` collective.
- **Public API Documentation** — Every public function and struct must have a docstring including security considerations.
- **Zero-Warning Implementation** — All tests, `clippy`, and `rustfmt` must pass before submission.

### Error Handling Guidelines

**`InternalErrorDetailed`** is for internal logging only. Never return raw internal error details to an external caller:

```rust
// ✅ CORRECT: Log details internally, return generic error externally
.map_err(|e| {
    warn!("OPERATION_FAILED: {:?}", e); // Detail in logs
    ProtocolError::InternalError        // Generic for caller
})?;

// ❌ INCORRECT: Leaks internal implementation details
.map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;
```

### Side-Channel Resistance

All security-sensitive comparisons MUST be constant-time to prevent timing oracles:

```rust
// ✅ CORRECT: Constant-time comparison using `subtle`
use subtle::ConstantTimeEq;
if computed_mac.ct_eq(&stored_mac[..]).unwrap_u8() == 0 { ... }

// ❌ INCORRECT: Standard comparison is a timing oracle
if computed_mac_hex != stored_mac_hex { ... }
```

### Submission Process

1. Fork and create a feature branch.
2. Run `cargo test --all` to verify logic.
3. Run `cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used` for linting.
4. Run `cargo fmt --all` for formatting.
5. Run `cargo audit` to check for CVEs in dependencies.
6. Submit a Pull Request with a clear description and justification for changes.

### Vulnerability Disclosure

**Do not open public issues for security vulnerabilities.**  
Please report security concerns privately to:  
`contact.sibna.dev`
