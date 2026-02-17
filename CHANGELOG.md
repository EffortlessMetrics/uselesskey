# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Deterministic negative-fixture helpers in `uselesskey-core`:
  - `negative::corrupt_pem_deterministic(pem, variant)`
  - `negative::corrupt_der_deterministic(der, variant)`
- Deterministic corruption convenience methods on key/cert fixtures:
  - RSA/ECDSA/Ed25519: `*_corrupt_deterministic(variant)`
  - X.509: `corrupt_cert_pem_deterministic(variant)` and `corrupt_cert_der_deterministic(variant)`
- New `uselesskey-token` microcrate:
  - `TokenFactoryExt` (`fx.token(label, spec)`)
  - `TokenSpec::{api_key,bearer,oauth_access_token}`
  - Authorization header helpers and deterministic token generation
- New facade `token` feature in `uselesskey`, included in `full`

## [0.2.1] - 2026-02-16

### Changed

- Release prep updates for release metadata and manifest version alignment.

## [0.2.0] - 2026-02-14

### Added

- `uselesskey-rustcrypto` adapter crate for RustCrypto native types (`rsa`, `p256`, `p384`, `ed25519-dalek`, `hmac`)
- `uselesskey-aws-lc-rs` adapter crate for `aws-lc-rs` native types with `native` feature for wasm-safe builds
- `ChainNegative::RevokedLeaf` variant with CRL signed by intermediate CA (`uselesskey-x509`)
- `RustlsServerConfigExt` / `RustlsClientConfigExt` / `RustlsMtlsExt` config builders (`uselesskey-rustls`)
- `server_config_mtls_rustls_with_provider()` / `client_config_mtls_rustls_with_provider()` for mTLS with explicit crypto provider (`uselesskey-rustls`)
- `uselesskey-ring` adapter crate for `ring` 0.17 native signing key types
- Cross-key failure test in `uselesskey-jsonwebtoken`
- Deterministic-mode test in `uselesskey-ring`
- Per-crate README files for all adapter crates
- Crate-level `//!` docs for `uselesskey-hmac` and `uselesskey-jwk`
- "Why not just..." comparison section in root README
- README: X.509, adapter crates, TLS config builder, and ecosystem sections
- New examples demonstrating library capabilities:
  - `jwt_signing` - JWT signing with RSA/ECDSA/HMAC keys and JWK/JWKS outputs
  - `tls_server` - Certificate chain generation (Root CA → Intermediate → Leaf)
  - `negative_fixtures` - Invalid certificates/keys for testing error handling
- Expanded BDD test coverage with new feature files:
  - `chain.feature` - X.509 certificate chain scenarios (determinism, structure, SANs, negative fixtures)
  - `jwks.feature` - JWKS builder scenarios (multi-key, deterministic ordering, field validation)
  - `cross_key.feature` - Cross-key validation scenarios (algorithm mismatch, key type differences)
  - `edge_cases.feature` - Label edge cases, cache behavior, determinism edge cases
- Expanded existing BDD feature files with additional scenarios:
  - `rsa.feature` - RS384/RS512 variant scenarios
  - `hmac.feature` - HS384/HS512 variant scenarios
  - `x509.feature` - CRL/revoked leaf and hostname mismatch scenarios
  - `jwks.feature` - Rotation and additional field validation scenarios
- Comprehensive test suites for adapter crates:
  - `uselesskey-jsonwebtoken` - JWT signing/verification with all key types
  - `uselesskey-ring` - ring 0.17 key type conversion tests
  - `uselesskey-aws-lc-rs` - aws-lc-rs key type conversion tests
  - `uselesskey-rustcrypto` - RustCrypto type conversion tests
- BDD test runner expanded with step definitions for all new features
- Updated roadmap: moved completed items (cert chains, X.509 negatives, all adapter crates) from Planned to Implemented

## [0.1.0] - 2026-02-03

### Added

- Initial release
- Core factory with random and deterministic modes (order-independent BLAKE3 derivation)
- DashMap-based concurrent caching keyed by artifact identity
- RSA key fixture generation (PKCS#8/SPKI in PEM/DER) via `uselesskey-rsa`
- ECDSA key fixture generation (P-256/ES256, P-384/ES384) via `uselesskey-ecdsa`
- Ed25519 key fixture generation via `uselesskey-ed25519`
- HMAC secret fixture generation (HS256/HS384/HS512) via `uselesskey-hmac`
- X.509 self-signed certificate generation via `uselesskey-x509`
- X.509 certificate chain generation with root CA, intermediate CA, and leaf certificates
- Chain-level negative test fixtures (expired CA, wrong issuer, self-signed leaf, unknown CA, reversed chain)
- `uselesskey-rustls` adapter crate for `rustls-pki-types` integration
- 10-year default certificate validity for X.509 fixtures
- Key reuse optimization across negative fixture variants
- Identity PEM methods on X.509 chain fixtures
- JWK/JWKS output support with `JwksBuilder` (via `jwk` feature)
- Negative fixtures (corrupt PEM, truncated DER, mismatched keys)
- Tempfile output for libraries requiring file paths
- `uselesskey-jsonwebtoken` adapter crate for `jsonwebtoken` `EncodingKey`/`DecodingKey` integration
- Feature matrix checks via `cargo xtask feature-matrix`
- Publish dry-run command via `cargo xtask publish-check`
- Secret-shaped blob detection via `cargo xtask no-blob`
- PR-scoped `cargo xtask pr` runner with JSON receipt and summary reporting
