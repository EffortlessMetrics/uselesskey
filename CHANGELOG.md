# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-04-08

### Added

- Added `uselesskey-entropy` as a narrow public lane for deterministic
  high-entropy byte fixtures and scanner-safe placeholder data.
- Added `uselesskey-cli materialize` / `verify` manifest workflows, including
  build-time `OUT_DIR` examples for common shape-only fixtures and specialized
  RSA PKCS#8 materialization.
- Added `cargo xtask economics` and `cargo xtask audit-surface` so lane cost
  and advisory-island receipts are generated as first-class repo artifacts.

### Changed

- Reframed the public docs around lane choice first: entropy, token, semantic
  runtime fixtures, and build-time materialized fixtures.
- Made `uselesskey-cli` publishable and split the build-time consumer surface so
  shape-only materialization stays cheap while RSA materialization remains
  explicit via `rsa-materialize`.
- Added CI drift checks and receipt artifact uploads for dependency economics
  and audit-surface reports.

## [0.5.1] - 2026-03-27

### Added

- Added X.509 chain negatives for not-yet-valid leaf/intermediate fixtures and
  intermediate CA/key-usage path failures.

### Changed

- Refreshed workspace crate versions and release-facing dependency snippets for
  the `0.5.1` release line.
- Updated dependency maintenance lanes to `toml 1.1.0`, `insta 1.47.0`, and
  `sha2 0.11.0`, with the matching RustCrypto/HMAC compatibility surface kept
  green across adapters and fuzz targets.

### Fixed

- Preserved default-chain determinism after the X.509 negative-fixture plumbing
  expansion, so unchanged `ChainSpec` inputs keep their prior certificate
  fingerprints.
- Added chain-serial regression coverage that kills the missed
  `next_serial_number` mutant.
- Aligned the fuzz RustCrypto/HMAC dependency surface with the merged adapter
  dependency updates so post-merge CI stays green.

## [0.5.0] - 2026-03-25

### Added

- Added a reusable adapter template with a scoped checklist for public-surface
  additions and release-readiness requirements.
- Added the `uselesskey-jose-openid` adapter crate for JOSE/OpenID-oriented
  native key conversion flows and example coverage.
- Added the `uselesskey-pgp-native` adapter crate for native OpenPGP key handling
  and example coverage.

### Changed

- Added `docs-sync` and metadata-driven docs checks to PR validation, including
  release-facing example/snippet verification.
- Moved README, adapter matrix, and workspace documentation to the cleaner
  adapter-wave wording and boundary-focused guidance.

## [0.4.1] - 2026-03-17

### Added

- Consistent `label()` / `spec()` accessors across RSA, ECDSA, Ed25519, HMAC,
  token, and OpenPGP fixture types.
- `cargo xtask publish-preflight` now validates versioned `uselesskey*`
  dependency snippets in release-facing docs so stale README examples are
  caught before publish.

### Changed

- Workspace manifests and versioned dependency snippets now target `0.4.1`
  ahead of the release tag.
- Release and roadmap docs now reflect the shipped RNG-boundary work and the
  current publish flow.

### Fixed

- `rustfmt.toml` now explicitly matches the workspace's Rust 2024 edition.
- `uselesskey-interop-tests` now explicitly forbids unsafe code like the rest
  of the workspace.
- Accessor mutation coverage is hardened, including the singleton Ed25519-spec
  equivalent-mutant exclusion and a fast HMAC `kid()` regression killer.

## [0.4.0] - 2026-03-13

### Changed

- Public RNG-facing APIs are now seed-oriented instead of exposing `rand` or
  `rand_core` types through the published surface.
- Seed/core/helper crates now use the newer `rand 0.10` line internally,
  while the stable crypto-edge crates remain on the intentional legacy island
  until a later convergence pass.
- Support crates and fuzz targets were updated to consume the seed-oriented
  helper APIs instead of the old RNG-shaped entry points.

### Added

- `Seed::fill_bytes(&mut [u8])` as the stable byte-oriented boundary for
  deterministic helper and fixture code.

### Notes

- This release does not claim full RNG convergence across every crypto-edge
  crate yet. Stable RSA and Ed25519 generation paths remain intentionally
  isolated on the legacy RNG line for now.

## [0.3.0] - 2026-03-12

### Changed

- `uselesskey` facade default features are now empty instead of enabling RSA by
  default. Consumers now opt into RSA, token, X.509, or other fixture families
  explicitly.
- Token-only facade usage is now documented as:
  `uselesskey = { version = "0.3.0", default-features = false, features = ["token"] }`
  so lightweight consumers avoid pulling `uselesskey-rsa` and `rsa`.

### Added

- `Seed::from_text(&str)` for deterministic seed derivation from stable text.
- `Factory::deterministic_from_str(&str)` as a facade-friendly convenience for
  test helpers that only need stable string seeds.
- A token-only consumer fixture and governance checks proving token-only facade
  usage compiles and that the resolved graph excludes `uselesskey-rsa` and
  `rsa`.
- Facade smoke coverage for order-independent determinism, X.509 re-exports,
  and published-facade-style consumer usage.

## [0.2.0] - 2026-03-06

### Added

#### Testing infrastructure

- **Snapshot tests** — `insta`-based snapshot coverage across all key-type crates
  (RSA, ECDSA, Ed25519, HMAC, Token, PGP) and adapter crates (jsonwebtoken,
  rustls, ring, rustcrypto, aws-lc-rs, tonic), pinning PEM/DER/JWK output
  formats and negative-fixture shapes
- **Property-based tests** — `proptest` strategies for core derivation,
  caching invariants, seed stability, and microcrate contracts
- **BDD scenarios** — Cucumber feature files covering all key types, X.509
  self-signed and chain certificates, JWKS ordering, cross-key validation,
  negative fixtures (corrupt PEM, truncated DER, mismatch, expired/revoked
  certs), and adapter round-trips
- **Cross-adapter interop tests** — signing round-trip and TLS handshake tests
  across rustls, ring, rustcrypto, and aws-lc-rs backends
  (`uselesskey-interop-tests`)
- **Determinism regression snapshots** — hardcoded expected-value tests ensuring
  derivation stability across releases
- **Security invariant tests** — dedicated tests verifying `Debug` impls never
  expose key material
- **Fuzz targets** — cargo-fuzz targets for negative fixture functions, parser
  stress, and seed edge cases
- **Mutant kills** — targeted tests closing surviving mutants in core microcrates
- **Error boundary tests** — edge-case and error-path coverage for factory,
  cache, and adapter crates
- **Feature-flag isolation tests** — verify each feature gate enables exactly
  the expected API surface
- **API surface stability tests** — smoke tests ensuring public API shape
  does not regress
- **Dependency guard tests** — license policy and RNG-pinning validation
- **Concurrency stress tests** — thread-safety and cache coherence under
  parallel access
- **Comprehensive microcrate tests** — coverage gap fills for core-cache,
  core-kid, core-negative, core-x509-spec, core-x509-derive, core-sink,
  jwk-builder, jwk-shape, and more

#### Refactored

- Extracted `uselesskey-token-spec` microcrate for stable token specification
  enum, shared across token generators

#### Documentation

- Polished README with quick-start examples, feature matrix, adapter guide,
  and negative-fixture documentation
- Per-crate README files for crates.io readiness
- Comprehensive architecture docs covering all 48 workspace crates
- Publish-ready `Cargo.toml` metadata across all crates (homepage, categories,
  keywords)

#### CI & tooling

- Installed `typos-cli` and `cargo-deny` in CI workflow
- Added `.typos.toml` for false-positive exclusions on crypto test data
- Scoped CI mutation testing to fast core microcrates; algorithm and adapter
  crates are mutant-tested only when directly impacted in PR runs
- Added `workflow_dispatch` trigger for manual CI invocations
- Increased CI timeouts (PR: 45 min, main: 75 min) for workspace growth
- Switched CI tool installation to `taiki-e/install-action` for pre-built
  binaries (faster cold starts)

#### Fixed

- Platform-dependent PGP RSA-3072 binary lengths redacted in snapshot tests
- RUSTSEC-2025-0119 advisory added to `deny.toml` ignore list

## [0.1.0] - 2026-02-17

Initial public release. **uselesskey** generates deterministic and random
cryptographic key fixtures for testing — preventing secret-shaped blobs from
entering version control while giving tests realistic key formats.

### Added

#### Core engine

- **Deterministic mode** — order-independent BLAKE3 derivation:
  `master_seed + artifact_id → derived_seed → RNG → artifact`.
  Adding new fixtures never perturbs existing ones.
- **Random mode** — non-deterministic generation for one-off tests.
- **Concurrent cache** — DashMap-based, keyed by `(domain, label, spec, variant)`.
  Makes RSA keygen cheap enough to avoid committed fixtures.
- **`no_std` support** — core derivation, caching, and negative helpers work
  without `std` (`uselesskey-core` with `--no-default-features`).

#### Key types

- **RSA** — PKCS#8 / SPKI in PEM / DER (2048, 3072, 4096 bits) via `RsaFactoryExt`
- **ECDSA** — P-256 / ES256, P-384 / ES384 via `EcdsaFactoryExt`
- **Ed25519** via `Ed25519FactoryExt`
- **HMAC** — HS256 / HS384 / HS512 via `HmacFactoryExt`
- **Token** — API-key, bearer, OAuth access-token shapes via `TokenFactoryExt`
- **OpenPGP** — RSA-2048/3072 and Ed25519 armored keyblocks via `PgpFactoryExt`

#### X.509 certificates

- Self-signed certificate generation via `X509FactoryExt`
- Certificate chain generation (root CA → intermediate CA → leaf)
- Chain-level negative fixtures (expired CA, wrong issuer, self-signed leaf,
  unknown CA, reversed chain, revoked leaf with CRL)
- 10-year default certificate validity; key reuse across negative variants
- TLS config builders: `RustlsServerConfigExt`, `RustlsClientConfigExt`,
  `RustlsMtlsExt` with explicit crypto-provider selection

#### JWK / JWKS

- Typed JWK / JWKS output with `JwksBuilder` and stable kid-based ordering

#### Negative fixtures

- **Corrupt PEM** — bad base64, wrong headers, truncated, deterministic
  corruption variants (`corrupt_pem_deterministic`)
- **Truncated DER** — deterministic corruption via `corrupt_der_deterministic`
- **Mismatched keypairs** — valid public key that doesn't match the private key
- Deterministic corruption convenience methods on all key-type and X.509 fixtures

#### Adapter crates

- **`uselesskey-jsonwebtoken`** — `jsonwebtoken` `EncodingKey` / `DecodingKey`
- **`uselesskey-rustls`** — `rustls-pki-types` certificates and private keys
- **`uselesskey-ring`** — `ring` 0.17 native signing key types
- **`uselesskey-rustcrypto`** — RustCrypto native types (`rsa`, `p256`, `p384`,
  `ed25519-dalek`, `hmac`)
- **`uselesskey-aws-lc-rs`** — `aws-lc-rs` native types with `native` feature
- **`uselesskey-tonic`** — gRPC TLS adapter: one-liner server / client / mTLS
  config builders for `tonic::transport`

#### Documentation

- Module-level `//!` docs and doc-tests on all public API items
- Per-crate README files for crates.io readiness
- Examples: `basic_rsa`, `all_key_types`, `jwk_jwks`, `jwt_signing`,
  `tls_server`, `negative_fixtures`

#### Tooling

- `cargo xtask ci` — full CI pipeline (fmt, clippy, tests, feature matrix,
  dep-guard, BDD, no-blob, mutants, fuzz)
- `cargo xtask pr` — PR-scoped tests with JSON receipt and summary reporting
- `cargo xtask feature-matrix` — default, no-default, each-feature, all-features
- `cargo xtask publish-check` / `cargo xtask publish-preflight` — publish dry-runs
- `cargo xtask no-blob` — secret-shaped blob detection
- `cargo xtask dep-guard` — guard against multiple versions of pinned deps

### Architecture

Repository organised into four layers:

**Facade**

| Crate | Purpose |
|-------|---------|
| `uselesskey` | Public API facade — re-exports stable surface |

**Core microcrates**

| Crate | Purpose |
|-------|---------|
| `uselesskey-core` | Factory, derivation, caching, negative helpers |
| `uselesskey-core-base62` | Base-62 generation |
| `uselesskey-core-cache` | DashMap-based concurrent cache |
| `uselesskey-core-factory` | Factory construction helpers |
| `uselesskey-core-hash` | BLAKE3 hashing primitives |
| `uselesskey-core-hmac-spec` | `HmacSpec` model |
| `uselesskey-core-id` | `ArtifactId` type |
| `uselesskey-core-jwk` | Typed JWK / JWKS models |
| `uselesskey-core-jwk-builder` | JWK builder logic |
| `uselesskey-core-jwk-shape` | JWK shape types |
| `uselesskey-core-jwks-order` | Stable kid-based JWKS ordering |
| `uselesskey-core-keypair` | Keypair abstraction |
| `uselesskey-core-keypair-material` | Raw key-material types |
| `uselesskey-core-kid` | Key-ID generation |
| `uselesskey-core-negative` | Negative-fixture orchestration |
| `uselesskey-core-negative-der` | DER corruption helpers |
| `uselesskey-core-negative-pem` | PEM corruption helpers |
| `uselesskey-core-rustls-pki` | rustls PKI type adapters |
| `uselesskey-core-seed` | Seed derivation |
| `uselesskey-core-sink` | Output-sink abstraction |
| `uselesskey-core-token` | Token generation core |
| `uselesskey-core-token-shape` | Token shape types |
| `uselesskey-core-x509` | X.509 core (negative + spec re-exports) |
| `uselesskey-core-x509-chain-negative` | Chain negative-policy types |
| `uselesskey-core-x509-derive` | X.509 derivation helpers |
| `uselesskey-core-x509-negative` | X.509 negative-fixture types |
| `uselesskey-core-x509-spec` | X.509 spec models and encoding |

**Key-type & adapter crates**

| Crate | Purpose |
|-------|---------|
| `uselesskey-rsa` | RSA fixtures (`RsaFactoryExt`) |
| `uselesskey-ecdsa` | ECDSA fixtures (`EcdsaFactoryExt`) |
| `uselesskey-ed25519` | Ed25519 fixtures (`Ed25519FactoryExt`) |
| `uselesskey-hmac` | HMAC fixtures (`HmacFactoryExt`) |
| `uselesskey-token` | Token fixtures (`TokenFactoryExt`) |
| `uselesskey-pgp` | OpenPGP keyblock fixtures (`PgpFactoryExt`) |
| `uselesskey-x509` | X.509 certificate fixtures (`X509FactoryExt`) |
| `uselesskey-jwk` | JWK facade (re-exports `uselesskey-core-jwk`) |
| `uselesskey-jsonwebtoken` | `jsonwebtoken` adapter |
| `uselesskey-rustls` | `rustls` / `rustls-pki-types` adapter |
| `uselesskey-ring` | `ring` adapter |
| `uselesskey-rustcrypto` | RustCrypto adapter |
| `uselesskey-aws-lc-rs` | `aws-lc-rs` adapter |
| `uselesskey-tonic` | `tonic` gRPC TLS adapter |

**Testing & tooling**

| Crate | Purpose |
|-------|---------|
| `uselesskey-bdd` | Cucumber BDD test runner |
| `uselesskey-bdd-steps` | BDD step definitions |
| `uselesskey-interop-tests` | Cross-adapter interop tests |
| `uselesskey-test-grid` | Test-grid generation |
| `uselesskey-feature-grid` | Feature-matrix checks |
| `tests` | Workspace-level integration tests |
| `xtask` | Build automation (`cargo xtask`) |
| `fuzz` | Fuzz targets (excluded from default workspace) |

### Testing

- **BDD** — Cucumber feature files covering RSA, ECDSA, Ed25519, HMAC, Token,
  PGP, X.509, certificate chains, JWKS, cross-key validation, negative
  fixtures, and edge cases
- **Property-based tests** — `proptest` for core derivation, caching, and
  microcrate invariants
- **Snapshot tests** — `insta` snapshots for all key-type and adapter crates
- **Fuzz targets** — 12+ targets covering derivation, negative fixtures, and
  under-fuzzed code paths
- **Cross-adapter interop** — signing and TLS round-trip tests across rustls,
  ring, rustcrypto, and aws-lc-rs
- **Security invariant** — `Debug` impls never expose key material (validated
  by dedicated tests)
- **Determinism regression** — hardcoded expected-value snapshots ensure
  derivation stability across releases

[Unreleased]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.1.0
