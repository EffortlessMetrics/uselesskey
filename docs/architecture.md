# Architecture

## Workspace layout

The workspace contains **49 crates** organized in four layers:
facade → algorithm crates → core microcrates → adapter crates, plus
testing/tooling crates that live outside the publish graph.

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

- `crates/uselesskey-jwk` — compatibility facade re-exporting
  `uselesskey-core-jwk`
- `crates/uselesskey-token-spec` — stable token specification enum
  (ApiKey, Bearer, OAuthAccessToken)

### Core microcrates

`uselesskey-core` is the public entry point; internally it re-exports a
set of focused microcrates that each own a single concern:

**Identity & derivation**

- `uselesskey-core-id` — artifact ID tuple (domain, label, spec, variant,
  derivation version)
- `uselesskey-core-seed` — seed parsing, redaction, and BLAKE3-backed
  entropy
- `uselesskey-core-hash` — length-prefixed BLAKE3 hashing for
  deterministic derivation
- `uselesskey-core-kid` — deterministic key-ID (kid) generation via
  base64url BLAKE3
- `uselesskey-core-base62` — bias-free base62 generation primitives

**Factory & caching**

- `uselesskey-core-factory` — factory orchestration: mode
  (Random/Deterministic), derivation dispatch, artifact generation
- `uselesskey-core-cache` — per-process artifact cache keyed by identity
  (DashMap + `Arc<dyn Any>`)
- `uselesskey-core-sink` — tempfile-backed artifact sinks for disk output

**Key material**

- `uselesskey-core-keypair` — shared PKCS#8/SPKI compatibility facade
- `uselesskey-core-keypair-material` — PKCS#8/SPKI key-material helpers
  with PEM/DER encoding
- `uselesskey-core-hmac-spec` — stable HMAC algorithm spec enum
  (HS256/HS384/HS512)

**JWK**

- `uselesskey-core-jwk` — typed JWK/JWKS models
- `uselesskey-core-jwk-builder` — JWKS builder with deterministic
  kid-based ordering
- `uselesskey-core-jwk-shape` — structured JWK types and JWKS collection
  serialization
- `uselesskey-core-jwks-order` — stable kid-sorted ordering helper

**Token**

- `uselesskey-core-token` — compatibility facade for token shape
  primitives
- `uselesskey-core-token-shape` — token generation primitives (API keys,
  bearer tokens)
- `uselesskey-core-token-oauth-shape` — OAuth access-token JWT-shape
  generation primitives

**Negative fixtures**

- `uselesskey-core-negative` — compatibility facade for DER/PEM
  corruption builders
- `uselesskey-core-negative-der` — DER corruption (truncation,
  byte-flipping)
- `uselesskey-core-negative-pem` — PEM corruption (deterministic
  `CorruptPem` strategies)

**X.509**

- `uselesskey-core-x509-spec` — X.509 spec models and stable encoders
  for certificates and chains
- `uselesskey-core-x509-derive` — deterministic X.509 helpers for time,
  serial numbers, and identity
- `uselesskey-core-x509` — X.509 policy helpers and negative-policy types
- `uselesskey-core-x509-negative` — X.509 negative-fixture policy
  helpers (expired, wrong-usage)
- `uselesskey-core-x509-chain-negative` — chain-level negative policies
  (hostname mismatch, revoked leaf)

**Adapter bridge**

- `uselesskey-core-rustls-pki` — rustls-pki-types adapter traits for
  converting fixtures to PKI types

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
