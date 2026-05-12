# Architecture

## Workspace layout

The workspace contains **48 crates** organized in four layers:
facade → algorithm crates → core microcrates → adapter crates, plus
testing/tooling crates that live outside the publish graph.

For the support boundary between public promises, published internal shards, and
workspace-only crates, see
[`docs/architecture/public-surface.md`](../architecture/public-surface.md).

### Facade

- `crates/uselesskey` — public facade re-exporting the stable API

### Algorithm crates (extension-trait pattern)

Each adds a `*FactoryExt` trait to `Factory`:

- `crates/uselesskey-rsa` — RSA keypair generator (RustCrypto `rsa`);
  PKCS#8/SPKI encodings, mismatch fixtures; optional `jwk` feature
- `crates/uselesskey-ecdsa` — ECDSA P-256/P-384 keypair generator;
  PKCS#8/SPKI encodings; optional `jwk` feature
- `crates/uselesskey-ed25519` — Ed25519 keypair generator;
  PKCS#8/SPKI encodings; optional `jwk` feature
- `crates/uselesskey-hmac` — HMAC secret generator (HS256/384/512);
  raw bytes + optional `jwk` feature
- `crates/uselesskey-token` — token fixture generator (API key, bearer,
  OAuth access token); deterministic JWT-shape outputs
- `crates/uselesskey-pgp` — OpenPGP key fixtures (armored and binary)
- `crates/uselesskey-x509` — X.509 certificate fixtures (self-signed +
  cert chains); negative fixtures: expired, hostname mismatch, unknown CA,
  revoked leaf (with CRL); deterministic validity/serial

### Shared spec/model crates

- `crates/uselesskey-jwk` — typed JWK/JWKS models, builders, ordering,
  and negative fixtures
- `crates/uselesskey-token` — token fixture owner, including token specs,
  base62 helpers, token-shape construction, and negative fixtures under
  `uselesskey_token::srp::*`

### Core internals (single-responsibility modules)

> **v0.8.0.** The v0.7.x line shipped each internal responsibility as its
> own published-internal compatibility shim crate (`uselesskey-core-cache`,
> `uselesskey-core-factory`, the `uselesskey-core-x509-*` shards,
> `uselesskey-token-spec`, `uselesskey-pgp-native`, `uselesskey-jose-openid`,
> etc.). v0.8.0 removes all 29 fully-folded shims; the canonical implementations
> live as `srp::*` modules under their owner crates and the responsibility
> boundary is preserved at the module level instead of the crate level.

`uselesskey-core` owns identity, derivation, factory/cache, sinks, and
generic negative-fixture helpers. The internal modules are documented but
not part of the public API surface:

- `uselesskey_core::srp::identity` — artifact ID tuple
  (domain, label, spec, variant, derivation version)
- `uselesskey_core::srp::seed` — seed parsing and redaction
- `uselesskey_core::srp::hash` — length-prefixed BLAKE3 hashing
- `uselesskey_core::srp::factory` — factory orchestration (Random /
  Deterministic mode, derivation dispatch)
- `uselesskey_core::srp::cache` — per-factory artifact cache (DashMap +
  `Arc<dyn Any>`) keyed by identity
- `uselesskey_core::srp::sink` — tempfile-backed artifact sinks
- `uselesskey_core::srp::keypair` / `keypair_material` — shared PKCS#8 /
  SPKI helpers used by RSA / ECDSA / Ed25519
- `uselesskey_core::srp::negative` — generic DER / PEM corruption helpers
  (`negative::der::*`, `negative::pem::*`)

Fixture-family crates own their model and shape internals as `srp::*`
modules:

- `uselesskey_jwk::srp::{kid, builder, ordering, shape}` — JWK / JWKS
  models, deterministic kid, JwksBuilder, stable kid ordering
- `uselesskey_token::srp::{base62, shape, spec}` — token shapes
  (api-key / bearer / OAuth), TokenSpec, base62 helper
- `uselesskey_x509::srp::{spec, derive, policy, negative, chain_negative}`
  — X.509 specs, deterministic derivation, single-cert and chain negative
  policies
- `uselesskey_hmac::srp::spec` — HmacSpec enum
- `uselesskey_rustls::srp::pki` — rustls-pki conversion traits
- `uselesskey_pgp::native` — native `pgp` crate adapter
  (`PgpNativeExt`, feature-gated on `native`)

### Adapter crates

Separate crates (not features) to decouple versioning from downstream
libraries:

- `crates/uselesskey-jsonwebtoken` — `jsonwebtoken::EncodingKey` /
  `DecodingKey`; optional per-key-type features
- `crates/uselesskey-rustls` — `rustls::pki_types` + `ServerConfig` /
  `ClientConfig` / mTLS builders; pluggable crypto provider
- `crates/uselesskey-ring` — `ring` 0.17 native signing key types
- `crates/uselesskey-rustcrypto` — RustCrypto native types (`rsa`,
  `p256`, `ed25519-dalek`, `hmac`)
- `crates/uselesskey-aws-lc-rs` — `aws-lc-rs` native key types; `native`
  feature for wasm-safe builds
- `crates/uselesskey-tonic` — `tonic::transport` TLS types; one-liner
  `ServerTlsConfig` / `ClientTlsConfig` / mTLS builders

### Testing & tooling

- `crates/uselesskey-bdd` — Cucumber BDD test runner; excluded from
  publish graph
- `crates/uselesskey-bdd-steps` — shared Cucumber step definitions
  across all key types and adapters
- `crates/uselesskey-interop-tests` — cross-backend interop tests
  (sign/verify/TLS round-trips)
- `crates/uselesskey-feature-grid` — canonical feature-matrix definitions
  for CI and BDD automation
- `crates/uselesskey-test-grid` — compatibility facade for feature-grid
  data exports
- `fuzz/` — cargo-fuzz targets (negative fixture functions + parser
  stress + seed edge cases)
- `xtask/` — build automation: fmt, clippy, test, nextest, deny,
  feature-matrix, dep-guard, no-blob, publish-check, publish-preflight,
  pr, ci, bdd, mutants, fuzz, coverage

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
  ├── PgpFactoryExt      (uselesskey-pgp)    → fx.pgp(label, spec)
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
