# Roadmap

This roadmap reflects the strategic direction for uselesskey as a **test-fixture layer** (not a crypto library).

## Current state (v0.1)

- [x] Core factory with random and deterministic modes
- [x] Order-independent derivation (BLAKE3 keyed hash)
- [x] DashMap-based concurrent caching
- [x] RSA fixtures via `RsaFactoryExt` trait
- [x] Output formats: PKCS#8 PEM/DER, SPKI PEM/DER
- [x] Tempfile outputs with restrictive permissions
- [x] Negative fixtures: corrupt PEM, truncated DER, mismatched keypairs

## v0.2 — Additional key types

**Goal:** Cover the common asymmetric key types used in JWT/TLS testing.

- [x] **ECDSA fixtures** (`uselesskey-ecdsa`)
  - P-256 (ES256), P-384 (ES384) via `p256`/`p384` crates
  - PKCS#8/SEC1 private key, SPKI public key
  - Same extension pattern: `EcdsaFactoryExt` trait

- [x] **Ed25519 fixtures** (`uselesskey-ed25519`)
  - Via `ed25519-dalek`
  - PKCS#8 private key, SPKI public key
  - `Ed25519FactoryExt` trait

## v0.3 — JWK/JWKS outputs

**Goal:** First-class JWK support for JWT testing workflows.

- [x] **JWK output methods** on all key types
  - `private_key_jwk()`, `public_key_jwk()`
  - Deterministic `kid` derived from artifact identity
  - Symmetric keys (HS256/HS384/HS512) for completeness

- [x] **JWKS builder**
  - Combine multiple public keys into a JWKS
  - Stable key ordering in deterministic mode

- [x] **HMAC fixtures** (`uselesskey-hmac`)
  - HS256/HS384/HS512 secrets
  - JWK/JWKS (`kty=oct`)

## v0.4 — X.509 certificates

**Goal:** Generate leaf certs and cert chains without OpenSSL.

- [x] **X.509 leaf certificates** (`uselesskey-x509`)
  - Self-signed certs via `rcgen` or `x509-cert`
  - Configurable: CN, SANs, validity period, key usage
  - `X509FactoryExt` trait

- [ ] **Cert chain fixtures**
  - Root CA → Intermediate → Leaf
  - Deterministic serial numbers

- [ ] **X.509 negative fixtures**
  - Expired certificates
  - Wrong SAN (hostname mismatch)
  - Unknown CA (untrusted root)
  - Revoked cert (with CRL/OCSP stub)

## v0.5 — Adapter crates

**Goal:** One-liner integration with popular Rust stacks.

- [ ] **`uselesskey-jsonwebtoken`**
  - Returns `jsonwebtoken::EncodingKey` / `DecodingKey` directly
  - Reduces boilerplate in JWT tests

- [ ] **`uselesskey-rustls`**
  - Returns `rustls::pki_types::PrivateKeyDer`, `CertificateDer`
  - Server/client config builders for TLS tests

- [ ] **`uselesskey-ring`** / **`uselesskey-aws-lc-rs`**
  - Native key types for `ring` and `aws-lc-rs` users

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

## Versioning policy

- **Derivation stability**: Changing the derivation algorithm requires bumping the derivation version field. Existing tests should not break.
- **Semver**: Breaking API changes bump the minor version until 1.0, then major version.
- **Feature flags**: New key types are opt-in via Cargo features to keep compile times reasonable.
