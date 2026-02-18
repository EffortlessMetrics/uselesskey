# Architecture

## Workspace layout

- `crates/uselesskey-core`
  - derivation (BLAKE3 keyed hash)
  - cache (DashMap keyed by ArtifactId)
  - sinks (tempfile outputs)
  - generic negative-fixture helpers (PEM/DER mangling)

- `crates/uselesskey-jwk`
  - typed JWK/JWKS helpers
  - stable key ordering via `JwksBuilder`

- `crates/uselesskey-rsa`
  - RSA keypair generator (RustCrypto `rsa`)
  - encodings: PKCS#8 private, SPKI public
  - mismatch fixtures (variant-derived keypairs)
  - optional `jwk` feature

- `crates/uselesskey-ecdsa`
  - ECDSA keypair generator (P-256/P-384)
  - encodings: PKCS#8 private, SPKI public
  - optional `jwk` feature

- `crates/uselesskey-ed25519`
  - Ed25519 keypair generator
  - encodings: PKCS#8 private, SPKI public
  - optional `jwk` feature

- `crates/uselesskey-hmac`
  - HMAC secret generator (HS256/384/512)
  - raw bytes + optional `jwk` feature

- `crates/uselesskey-token`
  - token fixture generator (API key, bearer, OAuth access token)
  - deterministic JWT-shape OAuth access token outputs

- `crates/uselesskey-x509`
  - X.509 certificate fixtures (self-signed + cert chains)
  - Root CA → Intermediate → Leaf chain generation
  - Negative fixtures: expired, hostname mismatch, unknown CA, revoked leaf (with CRL)
  - deterministic validity/serial in deterministic mode

- `crates/uselesskey-jsonwebtoken`
  - adapter: returns `jsonwebtoken::EncodingKey` / `DecodingKey` directly
  - optional features per key type (`rsa`, `ecdsa`, `ed25519`, `hmac`)

- `crates/uselesskey-rustls`
  - adapter: returns `rustls::pki_types::PrivateKeyDer`, `CertificateDer`
  - `tls-config` feature: `ServerConfig` / `ClientConfig` / mTLS builders
  - pluggable crypto provider (`rustls-ring` / `rustls-aws-lc-rs`)

- `crates/uselesskey-ring`
  - adapter: returns `ring` 0.17 native signing key types
  - `RsaKeyPair`, `EcdsaKeyPair`, `Ed25519KeyPair`

- `crates/uselesskey-rustcrypto`
  - adapter: returns RustCrypto native types
  - `rsa::RsaPrivateKey`, `p256::ecdsa::SigningKey`, `ed25519_dalek::SigningKey`, etc.

- `crates/uselesskey-aws-lc-rs`
  - adapter: returns `aws-lc-rs` native key types
  - `native` feature for wasm-safe builds

- `crates/uselesskey-tonic`
  - adapter: returns `tonic::transport` TLS types (`Identity`, `Certificate`)
  - one-liner `ServerTlsConfig` / `ClientTlsConfig` / mTLS builders from X.509 fixtures

- `crates/uselesskey`
  - facade re-exporting the stable public API

- `crates/uselesskey-bdd`
  - cucumber feature tests; kept out of the main crate’s dependency graph

- `fuzz/`
  - cargo-fuzz targets (negative fixture functions + parser stress)

- `xtask/`
  - build automation: fmt, clippy, test, nextest, deny, feature-matrix, no-blob, publish-check, pr, bdd, mutants, fuzz

## Deterministic derivation

In deterministic mode:

```
master_seed + artifact_id -> derived_seed -> RNG -> artifact
```

`artifact_id` is:

- domain (string, stable)
- label (string)
- spec_fingerprint (BLAKE3 hash of stable spec bytes)
- variant (string)
- derivation version (u16)

The derived seed uses a **keyed BLAKE3 hasher** with length-prefixing for strings.
This gives stable results and avoids order coupling.

## Cache behavior

A `Factory` caches artifacts per `ArtifactId`.

- deterministic mode: cache is an optimization; derivation is stable regardless
- random mode: cache makes repeated calls consistent within a process

Artifacts are stored as `Arc<dyn Any + Send + Sync>` and downcast on retrieval.

## Why "variant"

Variant strings solve a bunch of test cases cleanly:

- `"good"`: normal fixture
- `"mismatch"`: same label/spec, different keypair, used for mismatch negative tests
- `"corrupt:*"`: deterministic corruption patterns derived from variant identity

The variant is part of the artifact id, so it does not collide with the "good" fixture.

## Extension pattern

Key type support is added via extension traits rather than monolithic API growth:

```
Factory (core)
  ├── RsaFactoryExt      (uselesskey-rsa)     → fx.rsa(label, spec)
  ├── EcdsaFactoryExt    (uselesskey-ecdsa)   → fx.ecdsa(label, spec)
  ├── Ed25519FactoryExt  (uselesskey-ed25519) → fx.ed25519(label, spec)
  ├── HmacFactoryExt     (uselesskey-hmac)    → fx.hmac(label, spec)
  ├── TokenFactoryExt    (uselesskey-token)   → fx.token(label, spec)
  └── X509FactoryExt     (uselesskey-x509)    → fx.x509_self_signed(label, spec)
```

This pattern:

- Keeps compile times reasonable (opt-in via features)
- Allows independent versioning of key type crates
- Maintains a consistent API shape across key types
- Avoids dependency bloat in the core crate

Each extension crate depends on `uselesskey-core` and adds methods to `Factory` via its trait. The facade crate (`uselesskey`) re-exports enabled features.

## Adapter crates

Adapter crates provide native integration with downstream libraries. They are separate crates (not features) to avoid coupling uselesskey's versioning to downstream crate versions.

```
uselesskey-jsonwebtoken  → jsonwebtoken::EncodingKey / DecodingKey
uselesskey-rustls        → rustls-pki-types + ServerConfig/ClientConfig builders
uselesskey-tonic         → tonic::transport TLS identity/certificate/config builders
uselesskey-ring          → ring 0.17 native signing key types
uselesskey-rustcrypto    → RustCrypto native types (rsa, p256, p384, ed25519-dalek, hmac)
uselesskey-aws-lc-rs     → aws-lc-rs native key types
```

## CI scoping

Pull requests run `cargo xtask pr`, which scopes tests based on `git diff` and runs
the full suites relevant to changed areas. Pushes to `main` run the full `cargo xtask ci`
pipeline.
