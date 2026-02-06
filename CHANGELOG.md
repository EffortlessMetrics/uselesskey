# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- ECDSA key fixture generation (P-256/ES256, P-384/ES384) via `uselesskey-ecdsa`
- Ed25519 key fixture generation via `uselesskey-ed25519`
- HMAC secret fixture generation (HS256/HS384/HS512) via `uselesskey-hmac`
- X.509 self-signed certificate generation via `uselesskey-x509`
- `uselesskey-jsonwebtoken` adapter crate for `jsonwebtoken` `EncodingKey`/`DecodingKey` integration
- Feature matrix checks via `cargo xtask feature-matrix`
- Publish dry-run command via `cargo xtask publish-check`
- Secret-shaped blob detection via `cargo xtask no-blob`
- PR-scoped `cargo xtask pr` runner that selects suites based on `git diff` and emits a JSON receipt
- Receipt runner with summary reporting and timing for steps

## [0.1.0] - 2025-02-03

### Added

- Initial release
- RSA key fixture generation (PKCS#8/SPKI in PEM/DER)
- ECDSA key fixture generation (P-256/ES256, P-384/ES384)
- Ed25519 key fixture generation
- X.509 self-signed certificate generation
- Deterministic mode with order-independent derivation
- Negative fixtures (corrupt PEM, truncated DER, mismatched keys)
- JWK/JWKS output support (via `jwk` feature)
- Tempfile output for libraries requiring file paths
