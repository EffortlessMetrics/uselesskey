# Requirements v0.3

This document is the executable requirement spec for uselesskey v0.3+.
It captures the v0.3 surface, determinism guarantees, and operational gates.

## North star

uselesskey generates real-looking key/cert artifacts at runtime (deterministically or randomly)
so repos do not commit secret-shaped fixtures while still testing real parsing/verification paths.

## Product requirements

### Key fixture generation

- RSA (RS256)
- ECDSA (ES256/ES384)
- Ed25519 (EdDSA)
- HMAC (HS256/HS384/HS512)

### Format outputs

Asymmetric keys:
- PKCS#8 private key: PEM + DER
- SPKI public key: PEM + DER
- JWK: public + private
- JWKS: single-key + multi-key

HMAC:
- raw secret bytes
- JWK/JWKS (`kty=oct`, `k`)

X.509:
- cert PEM + DER
- key PEM
- chain PEM
- tempfiles

### Negative fixtures

- mismatched public key
- corrupt PEM variants (BadHeader, etc.)
- truncated DER
- expired / not-yet-valid X.509

## System requirements

### Determinism contract

- Deterministic factory: same `(seed, domain, label, spec, variant)` => same artifact bytes
- Order-independent: generating artifact A must not affect artifact B
- Cache-clear must not change deterministic artifacts

### Variant in identity

Variants are part of the cache key (`good`, `mismatch`, `corrupt:*`, `truncated:*`).

### Feature gating

- Facade crate stays thin
- Algorithms gated: `rsa`, `ecdsa`, `ed25519`, `hmac`, `x509`
- `jwk` gated to avoid `serde_json` unless requested

## Release/ops requirements

### Publishability

- Crates are publishable in dependency order
- `cargo publish --dry-run` succeeds in order

### CI guarantees

- Feature matrix checks (default, no-default, each feature, all-features)
- BDD suite runs
- Fuzz + mutants (PR-scoped; full on main)
- Receipts emitted for cockpit ingestion

### Documentation

- Quickstart examples (JWT + JWKS, tempfiles)
- Clear stability promises (derivation versioning)
- Feature matrix documented

## Acceptance gates

### Milestone 1: v0.3 surface

- `cargo test -p uselesskey --no-default-features --features "rsa,jwk"`
- `cargo test -p uselesskey --no-default-features --features "ecdsa,jwk"`
- `cargo test -p uselesskey --no-default-features --features "ed25519,jwk"`
- `cargo test -p uselesskey --no-default-features --features "hmac,jwk"`
- `cargo test -p uselesskey --all-features`

### Milestone 2: deterministic X.509

- `cargo test -p uselesskey-x509 --all-features`
- `cargo test -p uselesskey-bdd --test bdd`

### Milestone 3: publishability

- `cargo xtask publish-check`
- `cargo publish --dry-run -p uselesskey` (after dependencies)

### Milestone 4: CI + hygiene

- `cargo xtask ci`
- `cargo xtask pr`
- `target/xtask/receipt.json` is present and parseable

### Milestone 5: ergonomics

- `cargo test --examples --features "full"`
- Examples referenced from README
