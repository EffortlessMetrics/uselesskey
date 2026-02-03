# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**uselesskey** is a Rust test utility library that generates deterministic and random cryptographic key fixtures for testing. It prevents committing secret-shaped blobs (PEM, DER, tokens) into version control while allowing tests to work with realistic key formats.

## Build Commands

```bash
cargo xtask ci              # Main CI pipeline: fmt check + clippy + test (use this before commits)
cargo xtask test            # Run all tests with all features
cargo xtask fmt --fix       # Fix formatting
cargo xtask clippy          # Run clippy with -D warnings
cargo xtask bdd             # Run Cucumber BDD tests
cargo xtask fuzz            # Fuzz testing (requires cargo-fuzz)
cargo xtask mutants         # Mutation testing (requires cargo-mutants)
cargo xtask deny            # License/advisory checks (requires cargo-deny)
```

Run a single test:
```bash
cargo test -p uselesskey-core test_name
cargo test -p uselesskey-rsa test_name
```

## Architecture

### Workspace Structure

- **`crates/uselesskey`** - Public facade crate, re-exports stable API
- **`crates/uselesskey-core`** - Core factory, derivation, caching, negative fixtures
- **`crates/uselesskey-rsa`** - RSA-specific fixtures via `RsaFactoryExt` trait
- **`crates/uselesskey-bdd`** - Cucumber BDD tests
- **`xtask`** - Build automation commands

### Key Concepts

**Factory**: Central struct managing artifact generation and caching. Operates in Random or Deterministic mode.

**Deterministic Derivation**: BLAKE3 keyed hash transforms `master_seed + artifact_id -> derived_seed -> RNG -> artifact`. ArtifactId is a tuple of (domain, label, spec_fingerprint, variant, derivation_version). Adding new fixtures doesn't perturb existing ones.

**Cache**: DashMap-based concurrent cache stores `Arc<dyn Any + Send + Sync>`.

**Negative Fixtures**: Corrupt PEM variants (`CorruptPem` enum), truncated DER, mismatched keypairs via `"mismatch"` variant.

### Extension Pattern

RSA support is added via the `RsaFactoryExt` trait which adds an `rsa()` method to Factory. Future key types (ECDSA, Ed25519) will follow this pattern.

## Design Constraints

1. **Derivation stability**: Keep deterministic derivation stable; bump derivation version if changing algorithm
2. **No key leakage**: Debug output must never print key material
3. **Small composable crates**: Prefer modular design over monolith
4. **No unsafe code**: All crates use `#![forbid(unsafe_code)]`

## Testing

- Unit/integration tests use `#[test]`, `proptest` (property-based), and `rstest` (parameterized)
- BDD tests in `crates/uselesskey-bdd/features/rsa.feature`
- Fuzz targets in `fuzz/fuzz_targets/`

## Configuration Files

- `rustfmt.toml` - Formatting: Unix newlines, crate-level imports
- `clippy.toml` - MSRV 1.88
- `deny.toml` - Allowed licenses: MIT, Apache-2.0, BSD-3-Clause, ISC, CC0-1.0
- `mutants.toml` - Mutation testing exclusions
