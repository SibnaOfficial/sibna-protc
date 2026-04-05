# Contributing to Sibna Protocol

We welcome contributions from the community. To maintain the cryptographic integrity and high-assurance standards of the Sibna Protocol, all contributors are expected to adhere to the following guidelines.

## Development Standards

### 1. Code Quality & Lints
All contributions must pass strict quality checks:
- **Zero Warnings**: Your code must compile with `cargo clippy --workspace -- -D warnings`.
- **Formatting**: Ensure code adheres to the project's `rustfmt.toml` (`cargo fmt --all`).
- **Tests**: Every new feature or bug fix must include corresponding unit or integration tests. All existing tests (`cargo test --workspace`) must pass.

### 2. Cryptographic Best Practices
When modifying security-critical logic:
- **Constant-Time Operations**: Use the `subtle` crate for all sensitive comparisons to prevent timing attacks.
- **Memory Security**: Ensure all sensitive data (keys, entropy) implements the `Zeroize` trait and is wiped from memory upon drop.
- **KDF Invariants**: Do not deviate from the established HKDF-SHA256 and BLAKE3-based transcript binding without prior architectural review.

## Contribution Process

1. **Issue Tracking**: Before starting work, please open an issue to discuss the proposed change. This avoids duplication of effort.
2. **Branching**: Create your feature branch from `main`.
3. **Atomic Commits**: Keep your commits small, focused, and well-documented.
4. **PR Review**: All pull requests require a technical review. Cryptographic changes require mandatory sign-off from a core security maintainer.

## Security Disclosure

If you discover a security vulnerability, do **not** open a public issue. Please report it privately to `security@sibna.dev`.

## Documentation

Ensure any changes to the protocol wire format or key derivation logic are accurately reflected in the **[Protocol Specification](PROTOCOL_SPECIFICATION.md)**.
