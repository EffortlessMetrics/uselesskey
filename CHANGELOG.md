# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- PR-scoped `cargo xtask pr` runner that selects suites based on `git diff` and emits a JSON receipt.

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
