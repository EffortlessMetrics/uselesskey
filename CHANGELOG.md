# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-17

### Added

#### New crates

- **`uselesskey-token`** — token-shaped fixture generation:
  - `TokenFactoryExt` (`fx.token(label, spec)`)
  - `TokenSpec::{api_key, bearer, oauth_access_token}`
  - Authorization header helpers and deterministic token generation
  - New facade `token` feature in `uselesskey`, included in `full`
- **`uselesskey-pgp`** — OpenPGP keyblock fixtures:
  - `PgpFactoryExt` (`fx.pgp(label, spec)`)
  - `PgpSpec::{rsa_2048, rsa_3072, ed25519}`
  - Armored and binary keyblock outputs with mismatch/corruption helpers
  - New facade `pgp` feature in `uselesskey`, included in `all-keys` and `full`
- **`uselesskey-tonic`** — gRPC TLS adapter:
  - `TonicIdentityExt`, `TonicServerTlsExt`, `TonicClientTlsExt`, `TonicMtlsExt`
  - Converts `uselesskey-x509` fixtures into `tonic::transport` TLS types
  - One-liner server/client/mTLS config builders for gRPC tests

#### Deterministic negative fixtures

- `negative::corrupt_pem_deterministic(pem, variant)` and
  `negative::corrupt_der_deterministic(der, variant)` in `uselesskey-core`
- Deterministic corruption convenience methods on key/cert fixtures:
  - RSA/ECDSA/Ed25519: `*_corrupt_deterministic(variant)`
  - X.509: `corrupt_cert_pem_deterministic(variant)` and `corrupt_cert_der_deterministic(variant)`

#### `no_std` support

- `uselesskey-core` now compiles with `--no-default-features` (`no_std`):
  deterministic derivation, caching, and negative helpers work without `std`

#### Documentation and examples

- Module-level `//!` documentation for all public crates
- Doc-tests on public API items
- New examples: `basic_rsa`, `all_key_types`, `jwk_jwks`

#### Testing

- Expanded BDD feature files:
  - `chain.feature` — X.509 certificate chain scenarios (determinism, structure, SANs, negative fixtures)
  - `jwks.feature` — JWKS builder scenarios (multi-key, deterministic ordering, field validation)
  - `cross_key.feature` — cross-key validation (algorithm mismatch, key type differences)
  - `edge_cases.feature` — label edge cases, cache behavior, determinism edge cases
  - Additional scenarios in `rsa.feature`, `hmac.feature`, `x509.feature`
- Comprehensive adapter test suites for `uselesskey-jsonwebtoken`, `uselesskey-ring`,
  `uselesskey-aws-lc-rs`, `uselesskey-rustcrypto`, and `uselesskey-tonic`
- Snapshot tests (insta) for all key-type and adapter crates
- Property-based tests (proptest) for core microcrates
- Facade integration and end-to-end tests

### Fixed

- Killed 9 missed mutants in `uselesskey-core-negative-pem`
- Removed unused `testutil` imports from facade tests
- Corrected clippy warnings (`clone_on_copy`, `needless_borrow`, `collapsible_if`)

### Changed

- Bumped dependencies: `x509-parser` 0.16 → 0.18, `aws-lc-rs` 1.15 → 1.16, `tonic` 0.14.4 → 0.14.5

## [0.2.1] - 2026-02-16

### Changed

- Aligned release metadata and manifest versions across all workspace crates.

## [0.2.0] - 2026-02-14

### Added

#### New adapter crates

- **`uselesskey-rustcrypto`** — RustCrypto native types (`rsa::RsaPrivateKey`, `p256::ecdsa::SigningKey`, `p384`, `ed25519-dalek`, `hmac`)
- **`uselesskey-aws-lc-rs`** — `aws-lc-rs` native types with `native` feature for wasm-safe builds
- **`uselesskey-ring`** — `ring` 0.17 native signing key types

#### X.509 and TLS

- `ChainNegative::RevokedLeaf` variant with CRL signed by intermediate CA (`uselesskey-x509`)
- `RustlsServerConfigExt` / `RustlsClientConfigExt` / `RustlsMtlsExt` config builders (`uselesskey-rustls`)
- mTLS config builders with explicit crypto provider selection (`uselesskey-rustls`)

#### Documentation and examples

- Per-crate README files for all adapter crates
- Crate-level `//!` docs for `uselesskey-hmac` and `uselesskey-jwk`
- "Why not just…" comparison section in root README
- README sections for X.509, adapter crates, TLS config builders, and ecosystem positioning
- New examples: `jwt_signing`, `tls_server`, `negative_fixtures`

#### Testing

- Expanded BDD test coverage with new feature files (`chain`, `jwks`, `cross_key`, `edge_cases`)
  and additional scenarios in existing files (`rsa`, `hmac`, `x509`, `jwks`)
- Comprehensive test suites for all adapter crates
- Cross-key failure test in `uselesskey-jsonwebtoken`
- Deterministic-mode test in `uselesskey-ring`

## [0.1.0] - 2026-02-03

### Added

#### Core

- Core factory with random and deterministic modes (order-independent BLAKE3 derivation)
- DashMap-based concurrent caching keyed by `(domain, label, spec, variant)`
- Tempfile output for libraries requiring file paths

#### Key types

- **RSA** — PKCS#8/SPKI in PEM/DER (2048, 3072, 4096 bits) via `uselesskey-rsa`
- **ECDSA** — P-256/ES256, P-384/ES384 via `uselesskey-ecdsa`
- **Ed25519** via `uselesskey-ed25519`
- **HMAC** — HS256/HS384/HS512 via `uselesskey-hmac`

#### X.509

- Self-signed certificate generation via `uselesskey-x509`
- Certificate chain generation (root CA → intermediate CA → leaf)
- Chain-level negative fixtures (expired CA, wrong issuer, self-signed leaf, unknown CA, reversed chain)
- 10-year default certificate validity
- Key reuse optimization across negative fixture variants

#### JWK / JWKS

- JWK/JWKS output support with `JwksBuilder` (via `jwk` feature)

#### Negative fixtures

- Corrupt PEM (bad base64, wrong headers, truncated)
- Truncated DER
- Mismatched keypairs (valid public key that doesn't match the private key)

#### Adapters

- `uselesskey-jsonwebtoken` — `jsonwebtoken` `EncodingKey`/`DecodingKey` integration
- `uselesskey-rustls` — `rustls-pki-types` integration

#### Tooling

- Feature matrix checks via `cargo xtask feature-matrix`
- Publish dry-run command via `cargo xtask publish-check`
- Secret-shaped blob detection via `cargo xtask no-blob`
- PR-scoped `cargo xtask pr` runner with JSON receipt and summary reporting

[Unreleased]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.1.0
