# Contributing

## Setup

- Install Rust stable.
- Optional tools:
  - `cargo install cargo-mutants`
  - `cargo install cargo-fuzz`
  - `cargo install cargo-nextest`
  - `cargo install cargo-deny`

## Git Hooks (one-time)

```bash
cargo xtask setup
```

This sets `core.hooksPath` to `.githooks`, enabling:

- **pre-commit**: auto-formats and runs clippy fix on staged Rust/Cargo files.
- **pre-push**: runs the quality gate (fmt check + cargo check + clippy + test compile).

## Common commands

This repository uses `xtask` for automation. You can run these commands via `cargo xtask <cmd>`.

```bash
cargo xtask ci              # Main CI pipeline: fmt + clippy + tests + matrix + guard + bdd + no-blob + mutants + fuzz
cargo xtask pr              # PR-scoped tests based on git diff (emits JSON receipt)
cargo xtask test            # Run all tests with all features
cargo xtask fmt --fix       # Fix formatting
cargo xtask clippy          # Run clippy with -D warnings
cargo xtask bdd             # Run Cucumber BDD tests
cargo xtask fuzz            # Fuzz testing (requires cargo-fuzz)
cargo xtask mutants         # Mutation testing (requires cargo-mutants)
cargo xtask deny            # License/advisory checks (requires cargo-deny)
cargo xtask feature-matrix  # Run feature matrix checks (default, no-default, each feature, all-features)
cargo xtask publish-check   # Run publish dry-runs in dependency order
cargo xtask publish-preflight # Validate metadata + cargo package --no-verify
cargo xtask no-blob         # Enforce no secret-shaped blobs in test/fixture paths
cargo xtask dep-guard       # Guard against multiple versions of pinned deps
cargo xtask coverage        # Run code coverage (requires cargo-llvm-cov)
cargo xtask nextest         # Run tests via cargo-nextest (requires cargo-nextest)
cargo xtask lint-fix        # Auto-fix fmt + clippy, then verify
cargo xtask lint-fix --check # Check-only (no mutations)
cargo xtask gate            # Pre-push quality gate: fmt check + cargo check + clippy + test compile
cargo xtask bdd-matrix      # BDD matrix with feature sets
cargo xtask publish         # Publish all crates in dependency order
cargo xtask typos           # Spell check (requires typos installed)
cargo xtask typos --fix     # Auto-fix typos
cargo xtask setup           # Configure git hooks (sets core.hooksPath to .githooks)
```

## Architecture

- **`crates/uselesskey`**: Public facade crate, re-exports stable API under feature flags.
- **`crates/uselesskey-core`**: Core factory, derivation, caching, and negative fixture traits.
- **`crates/uselesskey-<type>`**: Individual key/certificate type implementations (RSA, ECDSA, Ed25519, HMAC, PGP, Token, X.509).
- **`crates/uselesskey-jwk`**: Typed JWK/JWKS helpers and `JwksBuilder`.
- **`crates/uselesskey-<adapter>`**: Adapt uselesskey fixtures to third-party library types. Adapter crates are separate crates (not features) to avoid coupling versioning.

Current adapter crates: `uselesskey-jsonwebtoken`, `uselesskey-rustls`, `uselesskey-tonic`, `uselesskey-ring`, `uselesskey-rustcrypto`, `uselesskey-aws-lc-rs`.

> BDD contributors: shared step definitions live in `crates/uselesskey-bdd-steps`.

### Adding a new Key Type

1. Create a new crate `crates/uselesskey-<name>`.
2. Define a `Spec` and a factory extension trait in that crate.
3. Implement `FactoryExt` on `uselesskey_core::Factory`.
4. Re-export the extension trait in the main `uselesskey` crate.
5. Add the crate to the workspace `members` in root `Cargo.toml`.
6. Add the crate to `publish_check()` order in `xtask/src/main.rs`.
7. Add the crate to `dependents()` in `xtask/src/plan.rs`.

## Design constraints

- **Deterministic Stability**: Keep deterministic derivation stable. If you must change an algorithm, bump the `derivation_version` in the artifact ID.
- **No Key Leakage**: Debug output (`impl Debug`) must **never** print key material.
- **Modularity**: Prefer small, composable crates over a monolith.
- **No Unsafe**: All crates must use `#![forbid(unsafe_code)]`.
