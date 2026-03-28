# Roadmap

This roadmap reflects the strategic direction for uselesskey as a **test-fixture layer** (not a crypto library).

## Now (v0.5.x)

*Post-release planning reset for the next cycle*

- [x] [Roadmap reset for v0.5.x][roadmap-followups]
- [x] Create milestones and execution issues from the follow-up plan
- [x] ADR: adapter acceptance criteria
- [x] ADR: public surface policy
- [x] Add docs metadata source and sync enforcement
- [x] Add examples-smoke validation in the docs/examples path

## Next (v0.5.2+)

*Under evaluation - Planned follow-up*

- [ ] JWK/JWKS and token-shape negative fixture follow-ons
- [ ] Docs/examples coverage for the remaining negative-fixture surface
- [ ] Performance benchmarks for key generation paths
- [ ] Release governance and post-release audit automation
- [ ] Export-bundle integration (`uselesskey bundle`, k8s/vault payload emitters, and reference manifests)

## Shipped

### v0.5.1 (2026-03-27)

*X.509 negative-fixture expansion and dependency-lane stabilization*

- Added the first X.509 chain-negative wave for not-yet-valid fixtures and
  intermediate path-validation failures, while preserving default deterministic
  certificate outputs.
- Landed the queued maintenance dependency refreshes, including `toml`,
  `insta`, and `sha2`, plus the supporting RustCrypto/HMAC compatibility fixes
  needed to keep adapters, fuzz targets, and CI aligned.
- Prepared the `0.5.1` release manifests, changelog, and release-facing
  dependency snippets.

### v0.5.0 (2026-03-25)

*Adapter-wave release and docs/infrastructure alignment*

- Added a reusable adapter-scaffold template and established adapter acceptance
  requirements.
- Added `uselesskey-jose-openid` and `uselesskey-pgp-native` adapter
  microcrates with runtime examples and smoke/integration coverage.
- Added docs metadata source, `docs-sync`, and examples-smoke coverage to PR
  checks, and aligned release-facing docs to avoid drift.

### v0.4.0 (2026-03)

*RNG boundary cleanup and API hardening*

- [x] Hide rand ABI behind seed boundaries
- [x] Public API no longer leaks rand types
- [x] `Seed` is now the stable boundary between user code and RNG
  implementation
- [x] Support crates and fuzz targets consume the seed-oriented helper APIs

### v0.3.0 (2026-03)

*Façade ergonomics and lightweight token path*

- [x] Empty façade defaults (no default features)
- [x] Token-only lightweight path
- [x] `Seed::from_text` for ergonomic seed creation
- [x] `Factory::deterministic_from_str` convenience method
- [x] Dogfooding smoke coverage via test fixtures
- [x] Updated documentation and README examples

### v0.2.x

*Core functionality - Key types, adapters, and X.509*

- [x] **ECDSA fixtures** (`uselesskey-ecdsa`)
  - P-256 (ES256), P-384 (ES384) via `p256`/`p384` crates
  - PKCS#8/SEC1 private key, SPKI public key
  - `EcdsaFactoryExt` trait
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
- [x] **X.509 cert chain fixtures** (`uselesskey-x509`)
  - Root CA → Intermediate → Leaf
  - Deterministic serial numbers and validity periods
  - Chain PEM (leaf + intermediate, no root) for standard TLS server usage
  - Individual cert access (root, intermediate, leaf)
- [x] **X.509 negative fixtures** (`uselesskey-x509`)
  - Expired leaf/intermediate certificates
  - Hostname mismatch (wrong SAN)
  - Unknown CA (untrusted root)
  - Revoked leaf with CRL signed by intermediate CA
  - Self-signed leaf, reversed chain, wrong issuer
- [x] **Token fixtures** (`uselesskey-token`)
  - API key, bearer token, and OAuth access token (JWT-shape) fixtures
  - `TokenFactoryExt` trait on `Factory`: `fx.token("issuer", TokenSpec::api_key())`
- [x] **OpenPGP fixtures** (`uselesskey-pgp`)
  - RSA 2048/3072 and Ed25519 transferable keys
  - Armored and binary keyblock outputs
  - `PgpFactoryExt` trait on `Factory`: `fx.pgp("issuer", PgpSpec::ed25519())`
- [x] **Deterministic corruption variants** (`uselesskey-core`)
  - `corrupt_pem_deterministic(pem, variant)` and `corrupt_der_deterministic(der, variant)`
  - Enables stable `corrupt:*` fixture patterns tied to artifact identity
- [x] **`no_std` support in `uselesskey-core`**
  - `std` is now an opt-out default feature
  - Deterministic derivation, artifact identity, and negative helpers compile without `std`
- [x] **Adapter crates**
  - `uselesskey-jsonwebtoken`: Returns `jsonwebtoken::EncodingKey` / `DecodingKey` directly
  - `uselesskey-rustls`: Returns `rustls::pki_types::PrivateKeyDer`, `CertificateDer`
  - `uselesskey-tonic`: Returns `tonic::transport::Identity` / `Certificate` from X.509 fixtures
  - `uselesskey-ring`: Native `ring` 0.17 signing key types
  - `uselesskey-aws-lc-rs`: Native `aws-lc-rs` key types with `native` feature for wasm-safe builds
  - `uselesskey-rustcrypto`: RustCrypto native types (`rsa::RsaPrivateKey`, `p256::ecdsa::SigningKey`, etc.)
- [x] **BDD test suite** (38 feature files, ~150+ scenarios)
  - RSA, ECDSA, Ed25519, HMAC, X.509, JWK, JWKS, chains, cross-key, JWT, TLS, PGP, tokens, negative fixtures, edge cases
- [x] **Examples** (22 runnable examples)
  - JWT signing, TLS server chains, negative fixtures, tempfiles, JWKS builder, PGP keys, tokens, adapter integration, gRPC TLS

### v0.1.x

*Foundation - Core factory and RSA*

- [x] Core factory with random and deterministic modes
- [x] Order-independent derivation (BLAKE3 keyed hash)
- [x] DashMap-based concurrent caching
- [x] RSA fixtures via `RsaFactoryExt` trait
- [x] Output formats: PKCS#8 PEM/DER, SPKI PEM/DER
- [x] Tempfile outputs with restrictive permissions
- [x] Negative fixtures: corrupt PEM, truncated DER, mismatched keypairs

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

[roadmap-followups]: roadmap-followups-0251.md
