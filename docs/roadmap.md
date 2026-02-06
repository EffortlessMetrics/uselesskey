# Roadmap

This roadmap reflects the strategic direction for uselesskey as a **test-fixture layer** (not a crypto library).

## Implemented

- [x] Core factory with random and deterministic modes
- [x] Order-independent derivation (BLAKE3 keyed hash)
- [x] DashMap-based concurrent caching
- [x] RSA fixtures via `RsaFactoryExt` trait
- [x] Output formats: PKCS#8 PEM/DER, SPKI PEM/DER
- [x] Tempfile outputs with restrictive permissions
- [x] Negative fixtures: corrupt PEM, truncated DER, mismatched keypairs
- [x] **ECDSA fixtures** (`uselesskey-ecdsa`)
  - P-256 (ES256), P-384 (ES384) via `p256`/`p384` crates
  - PKCS#8/SEC1 private key, SPKI public key
  - Same extension pattern: `EcdsaFactoryExt` trait
- [x] **Ed25519 fixtures** (`uselesskey-ed25519`)
  - Via `ed25519-dalek`
  - PKCS#8 private key, SPKI public key
  - `Ed25519FactoryExt` trait
- [x] **JWK output methods** on all key types
  - `private_key_jwk()`, `public_key_jwk()`
  - Deterministic `kid` derived from key material (stable in deterministic mode)
  - Symmetric keys (HS256/HS384/HS512) for completeness
- [x] **JWKS builder**
  - Combine multiple public keys into a JWKS
  - Stable key ordering in deterministic mode
- [x] **HMAC fixtures** (`uselesskey-hmac`)
  - HS256/HS384/HS512 secrets
  - JWK/JWKS (`kty=oct`)
- [x] **X.509 leaf certificates** (`uselesskey-x509`)
  - Self-signed certs via `rcgen`
  - Configurable: CN, SANs, validity period, key usage
  - `X509FactoryExt` trait
- [x] **`uselesskey-jsonwebtoken`**
  - Returns `jsonwebtoken::EncodingKey` / `DecodingKey` directly
  - Reduces boilerplate in JWT tests

## Planned

### X.509 — cert chains and negative fixtures

- [ ] **Cert chain fixtures**
  - Root CA → Intermediate → Leaf
  - Deterministic serial numbers and validity periods
  - Chain PEM (leaf + intermediate, no root) for standard TLS server usage
  - Individual cert access (root, intermediate, leaf)
- [x] **X.509 negative fixtures** (`uselesskey-x509`)
  - Expired leaf/intermediate certificates
  - Hostname mismatch (wrong SAN)
  - Unknown CA (untrusted root)
  - Revoked cert (with CRL/OCSP stub)

### Adapter crates

- [ ] **`uselesskey-rustls`**
  - Returns `rustls::pki_types::PrivateKeyDer`, `CertificateDer`
  - `ServerConfig` / `ClientConfig` / mTLS config builders (with `tls-config` feature)
  - Pluggable crypto provider support (`rustls-ring` / `rustls-aws-lc-rs`)
- [x] **`uselesskey-ring`**
  - Native `ring` 0.17 signing key types (`RsaKeyPair`, `EcdsaKeyPair`, `Ed25519KeyPair`)
- [x] **`uselesskey-aws-lc-rs`**
  - Native `aws-lc-rs` key types with `native` feature for wasm-safe builds
- [x] **`uselesskey-rustcrypto`**
  - RustCrypto native types (`rsa::RsaPrivateKey`, `p256::ecdsa::SigningKey`, etc.)
- [x] **BDD test suite** (15 feature files, ~150+ scenarios)
  - RSA, ECDSA, Ed25519, HMAC, X.509, JWK, JWKS, chains, cross-key, JWT, TLS, negative fixtures, edge cases
- [x] **Examples** (7 runnable examples)
  - JWT signing, TLS server chains, negative fixtures, tempfiles, JWKS builder

## Future considerations

Items under evaluation, not yet committed:

- **`no_std` core** — If demand exists for embedded/WASM test fixtures
- **Deterministic corruptions** — Variant-derived corruption patterns via RNG instead of hard-coded transforms
- **Token fixtures** — API keys, bearer tokens, OAuth tokens with realistic shapes
- **PGP key fixtures** — For projects testing PGP/GPG workflows

## Non-goals

These are explicitly out of scope:

- Production key management
- Hardware-backed keys (HSM, TPM)
- Rotation servers or key lifecycle management
- Perfect scanner evasion (if a scanner flags runtime output, that's a downstream issue)
- Signing/verification APIs (artifacts only)

## Versioning policy

- **Derivation stability**: Changing the derivation algorithm requires bumping the derivation version field. Existing tests should not break.
- **Semver**: Breaking API changes bump the minor version until 1.0, then major version.
- **Feature flags**: New key types are opt-in via Cargo features to keep compile times reasonable.
