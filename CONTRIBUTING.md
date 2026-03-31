# Contributing to Sibna Protocol

## Security First

This is a cryptographic library. Every contribution must follow these rules:

### Critical rules

- **No `.unwrap()` or `.expect()` in production code** — use `?` or explicit error handling
- **No new dependencies without security review** — run `cargo audit` before adding any crate
- **No custom cryptographic primitives** — use existing audited crates only (RustCrypto)
- **All public API must be documented** — security notes required for crypto functions
- **All tests must pass** including `cargo clippy -- -D warnings`

### Submitting changes

1. Fork the repository and create a feature branch
2. Run the full test suite: `cargo test --all`
3. Run Clippy: `cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used`
4. Run formatting: `cargo fmt --all`
5. Run security audit: `cargo audit`
6. Submit a pull request with a clear description

### Reporting vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Email: security@sibna.dev

See [SECURITY.md](SECURITY.md) for the full disclosure policy.

### Code of Conduct

Be respectful and constructive. Security research benefits everyone.
