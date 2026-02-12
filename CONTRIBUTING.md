# Contributing

## Setup

- Install Rust stable.
- Optional tools:
  - `cargo install cargo-mutants`
  - `cargo install cargo-fuzz`
  - `cargo install cargo-nextest`
  - `cargo install cargo-deny`

## Common commands

This repository uses `xtask` for automation. You can run these commands via `cargo xtask <cmd>`.

```bash
cargo xtask ci              # Main CI pipeline: fmt check + clippy + test
cargo xtask pr              # PR-scoped tests based on git diff
cargo xtask test            # Run all tests with all features
cargo xtask fmt --fix       # Fix formatting
cargo xtask clippy          # Run clippy with -D warnings
cargo xtask bdd             # Run Cucumber BDD tests
cargo xtask fuzz            # Fuzz testing
cargo xtask mutants         # Mutation testing
cargo xtask no-blob         # Enforce no secret-shaped blobs in test paths
```

## Architecture

- **`crates/uselesskey`**: Public facade crate, re-exports stable API.
- **`crates/uselesskey-core`**: Core factory, derivation, caching, and negative fixture traits.
- **`crates/uselesskey-<type>`**: Individual key/certificate type implementations (RSA, ECDSA, etc.).
- **`crates/uselesskey-<adapter>`**: Adapt uselesskey fixtures to third-party library types (e.g., `rustls`, `ring`).

### Adding a new Key Type

1. Create a new crate `crates/uselesskey-<name>`.
2. Define a `Spec` and a factory extension trait in that crate.
3. Implement `FactoryExt` on `uselesskey_core::Factory`.
4. Re-export the extension trait in the main `uselesskey` crate.

## Design constraints

- **Deterministic Stability**: Keep deterministic derivation stable. If you must change an algorithm, bump the `derivation_version` in the artifact ID.
- **No Key Leakage**: Debug output (`impl Debug`) must **never** print key material.
- **Modularity**: Prefer small, composable crates over a monolith.
- **No Unsafe**: All crates must use `#![forbid(unsafe_code)]`.
