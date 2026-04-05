# Contributing

We welcome contributions to the Sibna Protocol.

## Pull Requests

1. Fork the repository and create your branch from `main`.
2. Ensure your code compiles without warnings (`cargo clippy -- -D warnings`).
3. Run the full test suite (`cargo test --workspace`).
4. Keep commits atomic and document any API changes.

## Security Changes

If your pull request modifies cryptographic logic or changes the transport layer, please explicitly highlight these changes in the PR description. Security-sensitive changes will undergo mandatory review.

Code modifying cryptographic primitives must use constant-time operations (e.g., via the `subtle` crate) and ensure that sensitive variables implement `zeroize` upon drop.
