# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
