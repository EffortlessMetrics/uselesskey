# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

**uselesskey** is a Rust test utility library that generates deterministic and random cryptographic key fixtures for testing. It prevents committing secret-shaped blobs (PEM, DER, tokens) into version control while allowing tests to work with realistic key formats.

## Strategic Positioning

This is a **test-fixture layer**, not a crypto library. The positioning matters for API design and documentation tone.

### The problem we solve

Secret scanners have different behaviors that both cause friction:
- **GitGuardian** scans each commit in a PR, so "add then remove" still trips detection
- **GitHub push protection** requires removing a blocked secret from **all commits** before pushing again

Path ignores exist but require ongoing maintenance. This crate replaces "security policy + docs + exceptions" with "one dev-dependency."

### Why we exist (ecosystem gaps)

> Snapshot: last reviewed 2025-02-03. This is context, not a compatibility matrix.

| Existing solution | Gap uselesskey fills |
|-------------------|---------------------|
| `jwk_kit` | No deterministic-from-seed, no negative fixtures |
| `rcgen` | Deterministic mode not first-class |
| `test-cert-gen` | Shells out to OpenSSL |
| `x509-test-certs` | Commits key material (triggers scanners) |

### Core differentiators (preserve these)

1. **Order-independent determinism** — `seed + artifact_id → derived_seed → artifact`. This is the most defensible feature; most seeded approaches break when test order changes.

2. **Cache-by-identity** — Per-process cache keyed by `(domain, label, spec, variant)` makes RSA keygen cheap enough to avoid committed fixtures.

3. **Shape-first outputs** — Users ask for PKCS#8/SPKI/JWK/tempfiles, not crypto primitives.

4. **Negative fixtures first-class** — Corrupt PEM, truncated DER, mismatched keys, and deterministic corruption variants (`corrupt:*`).

### Design principles

- Keep the API ergonomic: one-liner creation (`fx.rsa("issuer", RsaSpec::rs256())`)
- Avoid production crypto expectations: this is for tests only
- Preserve derivation stability: bump version if algorithm changes
- Extension traits for new key types (not monolithic API growth)

## Build Commands

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
cargo xtask lint-fix --no-clippy # fmt only
cargo xtask gate            # Pre-push quality gate: fmt check + cargo check + clippy + test compile
cargo xtask typos           # Spell check (requires typos installed)
cargo xtask typos --fix     # Auto-fix typos
cargo xtask bdd-matrix      # BDD matrix with feature sets
cargo xtask publish         # Publish all crates in dependency order
cargo xtask setup           # Configure git hooks (sets core.hooksPath to .githooks)
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
- **`crates/uselesskey-core-jwk`** - Core typed JWK/JWKS models plus stable `JwksBuilder` ordering semantics
- **`crates/uselesskey-core-x509-spec`** - X.509 spec models and stable encoding helpers
- **`crates/uselesskey-core-x509`** - X.509 negative-policy types plus X.509 spec/derive re-exports
- **`crates/uselesskey-jwk`** - Compatibility facade re-exporting `uselesskey-core-jwk`
- **`crates/uselesskey-rsa`** - RSA fixtures via `RsaFactoryExt` trait
- **`crates/uselesskey-ecdsa`** - ECDSA (P-256/P-384) fixtures via `EcdsaFactoryExt` trait
- **`crates/uselesskey-ed25519`** - Ed25519 fixtures via `Ed25519FactoryExt` trait
- **`crates/uselesskey-hmac`** - HMAC (HS256/HS384/HS512) fixtures via `HmacFactoryExt` trait
- **`crates/uselesskey-token`** - Token fixtures (API key, bearer, OAuth/JWT-shape) via `TokenFactoryExt` trait
- **`crates/uselesskey-pgp`** - OpenPGP key fixtures (RSA/Ed25519, armored/binary) via `PgpFactoryExt` trait
- **`crates/uselesskey-x509`** - X.509 certificate fixtures via `X509FactoryExt` trait
- **`crates/uselesskey-jsonwebtoken`** - Adapter: `jsonwebtoken` integration
- **`crates/uselesskey-rustls`** - Adapter: `rustls` / `rustls-pki-types` integration
- **`crates/uselesskey-ring`** - Adapter: `ring` integration
- **`crates/uselesskey-rustcrypto`** - Adapter: RustCrypto integration
- **`crates/uselesskey-aws-lc-rs`** - Adapter: `aws-lc-rs` integration
- **`crates/uselesskey-tonic`** - Adapter: `tonic` gRPC TLS integration
- **`crates/uselesskey-bdd`** - Cucumber BDD tests
- **`crates/uselesskey-bdd-steps`** - BDD step definitions
- **`crates/uselesskey-interop-tests`** - Cross-adapter interop tests
- **`crates/uselesskey-feature-grid`** - Feature-matrix definitions
- **`crates/uselesskey-test-grid`** - Test-grid facade
- **`crates/uselesskey-token-spec`** - Token spec models
- **`tests/`** - Workspace-level integration tests
- **`xtask`** - Build automation commands

> See `docs/explanation/architecture.md` for the full 48-crate breakdown including core microcrates.

### Key Concepts

**Factory**: Central struct managing artifact generation and caching. Operates in Random or Deterministic mode.

**Deterministic Derivation**: BLAKE3 keyed hash transforms `master_seed + artifact_id -> derived_seed -> RNG -> artifact`. ArtifactId is a tuple of (domain, label, spec_fingerprint, variant, derivation_version). Adding new fixtures doesn't perturb existing ones.

**Cache**: DashMap-based concurrent cache stores `Arc<dyn Any + Send + Sync>`.

**Negative Fixtures**: Corrupt PEM variants (`CorruptPem` enum), truncated DER, mismatched keypairs via `"mismatch"` variant. X.509 negative fixtures include expired certs, hostname mismatch, unknown CA, and revoked leaf with CRL.

### Extension Pattern

Key type support is added via extension traits on `Factory`:
- `RsaFactoryExt` → `fx.rsa(label, spec)`
- `EcdsaFactoryExt` → `fx.ecdsa(label, spec)`
- `Ed25519FactoryExt` → `fx.ed25519(label, spec)`
- `HmacFactoryExt` → `fx.hmac(label, spec)`
- `TokenFactoryExt` → `fx.token(label, spec)`
- `PgpFactoryExt` → `fx.pgp(label, spec)`
- `X509FactoryExt` → `fx.x509_self_signed(label, spec)` / `fx.x509_chain(label, spec)`

Adapter crates (e.g. `uselesskey-jsonwebtoken`) are separate crates, not features, to avoid coupling versioning.

## Design Constraints

1. **Derivation stability**: Keep deterministic derivation stable; bump derivation version if changing algorithm
2. **No key leakage**: Debug output must never print key material
3. **Small composable crates**: Prefer modular design over monolith
4. **No unsafe code**: All crates use `#![forbid(unsafe_code)]`

## Testing

- Unit/integration tests use `#[test]`, `proptest` (property-based), and `rstest` (parameterized)
- `cargo xtask test` runs `--workspace --all-features --exclude uselesskey-bdd`
- `cargo xtask bdd` runs BDD tests separately with `--release` (RSA keygen is too slow in debug)
- BDD feature files in `crates/uselesskey-bdd/features/` covering all key types, X.509, JWK, negative fixtures, and edge cases
- Fuzz targets in `fuzz/fuzz_targets/`

## Configuration Files

- `rustfmt.toml` - Formatting: Unix newlines, crate-level imports
- `clippy.toml` - MSRV 1.92
- `deny.toml` - Allowed licenses: MIT, Apache-2.0, BSD-3-Clause, ISC, CC0-1.0
- `mutants.toml` - Mutation testing exclusions

## Git Hooks

The repo ships pre-commit and pre-push hooks in `.githooks/`. Activate them once:

```bash
cargo xtask setup   # sets core.hooksPath to .githooks
```

- **pre-commit**: runs `cargo xtask lint-fix` when staged `.rs`/`Cargo.toml`/`Cargo.lock` files are present, then re-stages the touched files.
- **pre-push**: runs `cargo xtask gate --check` (fmt check + cargo check + clippy + test compile).

### Agent workflow rules

- Never use `--no-verify` to bypass hooks.
- Rely on the pre-commit hook to auto-fix formatting; do not manually run `cargo fmt` before committing.
- If a hook fails, fix the underlying issue and retry.
