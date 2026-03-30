# uselesskey

[![CI](https://github.com/EffortlessMetrics/uselesskey/actions/workflows/ci.yml/badge.svg)](https://github.com/EffortlessMetrics/uselesskey/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/uselesskey.svg)](https://crates.io/crates/uselesskey)
[![docs.rs](https://docs.rs/uselesskey/badge.svg)](https://docs.rs/uselesskey)
[![MSRV](https://img.shields.io/badge/MSRV-1.92-blue.svg)](https://doc.rust-lang.org/cargo/reference/manifest.html#the-rust-version-field)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

*Deterministic cryptographic test fixtures for Rust.*

`uselesskey` is a **test-fixture factory**, not a crypto library. It generates key material, certificates, token-shaped fixtures, and negative artifacts at runtime so tests do not need committed PEM/DER/JWK blobs.

## Why this exists

`uselesskey` is a **test-fixture layer**, not a runtime crypto service.

Use it when you need realistic cryptographic fixtures without committing PEM/DER/JWK files.

It exists to remove this test friction:

- scanners inspect every commit in a PR, not just the final diff
- fake-looking keys still trigger policy, push protection, and review friction

`uselesskey` replaces security exceptions + path ignores + fixture directories with one dev-dependency and runtime generation.

> **Do not use this crate for production key generation or certificate management.**
> Deterministic mode is intentionally predictable by design. Random mode is for tests only.

## What problem it solves

Without this layer, teams commonly end up with one of these:

| Approach | Problem |
|----------|----------|
| Commit PEM/DER files | Triggers scanners and push protection |
| Generate keys ad hoc in tests | Repeated boilerplate, slow RSA, no shared determinism |
| Use raw crypto crates directly | You still have to assemble PEM/DER/JWK/X.509 shapes yourself |
| Use `rcgen` or other runtime crates directly | Useful, but not centered on fixture ergonomics, determinism, or negative cases |

`uselesskey` is built specifically for **test artifacts**.

## What you get

### Fixture families

- RSA (2048, 3072, 4096)
- ECDSA (P-256, P-384)
- Ed25519
- HMAC (HS256, HS384, HS512)
- OpenPGP (RSA 2048/3072, Ed25519)
- Token fixtures (API key, bearer, OAuth access-token / JWT shape)
- X.509 self-signed certificates and certificate chains

### Output shapes

- PKCS#8 PEM/DER
- SPKI PEM/DER
- OpenPGP armored and binary keyblocks
- JWK / JWKS
- tempfiles for path-based APIs
- X.509 leaves and chains, and negative variants

### Negative artifacts

- corrupt PEM
- truncated DER
- mismatched keypairs
- expired / revoked / hostname-mismatch / unknown-CA certificates

## Choose the smallest feature set

The `uselesskey` facade has an empty default feature set. Enable only the fixture families you need.

Common starting points:

```toml
# RSA fixtures
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa"] }
```

```toml
# Token-only fixtures, no RSA/X.509 pull-in
[dev-dependencies]
uselesskey = { version = "0.5.1", default-features = false, features = ["token"] }
```

```toml
# RSA + JWK/JWKS
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa", "jwk"] }
```

```toml
# X.509 fixtures
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["x509"] }
```

Use the facade for convenience. Depend on leaf crates only when compile-time minimization matters enough to justify the sharper API.

If you are unsure which flags to start with, start from [docs/how-to/choose-features.md](docs/how-to/choose-features.md).
For a crate-by-crate support contract (stable/incubating/experimental, audience, and publish status), see [docs/reference/support-matrix.md](docs/reference/support-matrix.md).

## Quick start

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

// Random mode: different keys every run
let fx = Factory::random();

// Deterministic mode: stable output for a seed string
let fx = Factory::deterministic_from_str("my-test-seed");

// Or use env-var seed with random fallback
let fx = Factory::deterministic_from_env("USELESSKEY_SEED")
    .unwrap_or_else(|_| Factory::random());

let rsa = fx.rsa("issuer", RsaSpec::rs256());

let pkcs8_pem = rsa.private_key_pkcs8_pem();
let spki_der = rsa.public_key_spki_der();
```

The core shape is always:

```text
(mode, domain, label, spec, variant) -> artifact
```

That keeps fixtures stable in deterministic mode and cacheable in both modes.

## Feature reminders for common snippets

- `rsa` for PEM/DER, tempfiles, and negative-key examples
- `rsa` + `jwk` for `public_jwk()` / `public_jwks()`
- `x509` for certificate, rustls, and tonic examples
- `token` for token-shaped fixtures only
- `pgp` for armored/binary OpenPGP fixtures

## Dependency Snippet Reminders

<!-- docs-sync:dependency-snippets-start -->
Dependency snippets:
- **Quick start (RSA)**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.5.1", features = ["rsa"] }
  ```


- **Token-only**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.5.1", default-features = false, features = ["token"] }
  ```


- **JWT/JWK**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.5.1", features = ["rsa", "jwk"] }
  ```


- **X.509 + rustls**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.5.1", features = ["x509"] }
  uselesskey-rustls = { version = "0.5.1", features = ["tls-config", "rustls-ring"] }
  ```


- **jsonwebtoken adapter**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.5.1", features = ["rsa", "ecdsa", "ed25519", "hmac"] }
  uselesskey-jsonwebtoken = { version = "0.5.1" }
  ```


- **JOSE/OpenID adapter**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.5.1", features = ["rsa", "ecdsa", "ed25519", "hmac"] }
  uselesskey-jose-openid = { version = "0.5.1" }
  ```


- **pgp-native adapter**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.5.1", features = ["pgp"] }
  uselesskey-pgp-native = { version = "0.5.1" }
  ```
<!-- docs-sync:dependency-snippets-end -->

### JWK / JWKS

Requires `features = ["rsa", "jwk"]`.

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};

let fx = Factory::random();
let rsa = fx.rsa("issuer", RsaSpec::rs256());

let jwk = rsa.public_jwk();
let jwks = rsa.public_jwks();
```

### Tempfiles

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};

let fx = Factory::random();
let rsa = fx.rsa("server", RsaSpec::rs256());

let keyfile = rsa.write_private_key_pkcs8_pem().unwrap();
assert!(keyfile.path().exists());
```

### X.509 Certificates

Requires `features = ["x509"]`.

Self-signed certificates for simple TLS tests:

```rust
use uselesskey::{Factory, X509FactoryExt, X509Spec};

let fx = Factory::random();
let cert = fx.x509_self_signed("my-service", X509Spec::self_signed("test.example.com"));

let cert_pem = cert.cert_pem();
let key_pem = cert.private_key_pkcs8_pem();
```

Three-level chains (root  intermediate  leaf):

```rust
use uselesskey::{Factory, X509FactoryExt, ChainSpec};

let fx = Factory::random();
let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

// Standard TLS server chain: leaf + intermediate, no root
let chain_pem = chain.chain_pem();

// Individual artifacts for custom setups
let root_pem = chain.root_cert_pem();
let leaf_key = chain.leaf_private_key_pkcs8_pem();
```

### X.509 negative fixtures

These are for error-path tests, not validation logic.

```rust
use uselesskey::{Factory, X509FactoryExt, ChainSpec};

let fx = Factory::random();
let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

// Expired leaf certificate
let expired = chain.expired_leaf();

// Hostname mismatch (SAN doesn't match expected hostname)
let wrong_host = chain.hostname_mismatch("wrong.example.com");

// Signed by an unknown CA (not in your trust store)
let unknown = chain.unknown_ca();

// Revoked leaf with CRL signed by the intermediate CA
let revoked = chain.revoked_leaf();
let crl_pem = revoked.crl_pem().expect("CRL present for revoked variant");
```

### Negative fixtures (keys)

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};
use uselesskey::negative::CorruptPem;

let fx = Factory::random();
let rsa = fx.rsa("issuer", RsaSpec::rs256());

let bad_pem = rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
let truncated = rsa.private_key_pkcs8_der_truncated(32);
let mismatched_pub = rsa.mismatched_public_key_spki_der();
```

### Token fixtures

Token fixtures are **artifact shapes**, not an auth framework. They exist so tests can use realistic-looking token values without committing blobs.

```rust
use uselesskey::{Factory, TokenFactoryExt, TokenSpec};

let fx = Factory::random();
let api_key = fx.token("billing", TokenSpec::api_key());
let bearer = fx.token("gateway", TokenSpec::bearer());
let oauth = fx.token("issuer", TokenSpec::oauth_access_token());

assert!(api_key.value().starts_with("uk_test_"));
assert!(bearer.authorization_header().starts_with("Bearer "));
assert_eq!(oauth.value().split('.').count(), 3);
```

## Adapter crates

Adapter crates are separate packages, not facade features. That keeps integration versioning explicit and avoids coupling the facade to every downstream ecosystem type.

Use them when you want **native third-party library types** returned directly from fixture artifacts.

### TLS config builders (`uselesskey-rustls`)

With the `tls-config` feature, build rustls configs in one step:

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["x509"] }
uselesskey-rustls = { version = "0.5.1", features = ["tls-config", "rustls-ring"] }
```

```rust
use uselesskey::{ChainSpec, Factory, X509FactoryExt};
use uselesskey_rustls::{RustlsServerConfigExt, RustlsClientConfigExt};

let fx = Factory::random();
let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

let server_config = chain.server_config_rustls();
let client_config = chain.client_config_rustls();
```

### ring signing keys (`uselesskey-ring`)

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa"] }
uselesskey-ring = { version = "0.5.1", features = ["all"] }
```

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
use uselesskey_ring::RingRsaKeyPairExt;

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let ring_kp = rsa.rsa_key_pair_ring();
```

### RustCrypto types (`uselesskey-rustcrypto`)

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa"] }
uselesskey-rustcrypto = { version = "0.5.1", features = ["all"] }
```

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
use uselesskey_rustcrypto::RustCryptoRsaExt;

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let rsa_pk = rsa.rsa_private_key();
```

### aws-lc-rs types (`uselesskey-aws-lc-rs`)

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa"] }
uselesskey-aws-lc-rs = { version = "0.5.1", features = ["native", "all"] }
```

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let lc_kp = rsa.rsa_key_pair_aws_lc_rs();
```

### gRPC TLS (`uselesskey-tonic`)

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["x509"] }
uselesskey-tonic = "0.5.1"
```

```rust
use uselesskey::{ChainSpec, Factory, X509FactoryExt};
use uselesskey_tonic::{TonicClientTlsExt, TonicServerTlsExt};

let fx = Factory::random();
let chain = fx.x509_chain("grpc", ChainSpec::new("test.example.com"));

let server_tls = chain.server_tls_config_tonic();
let client_tls = chain.client_tls_config_tonic("test.example.com");
```

## Runnable Examples

The [`crates/uselesskey/examples/`](crates/uselesskey/examples/) directory contains standalone programs. Because the facade default feature set is empty, run them with `cargo run -p uselesskey --example <name> --features "<flags>"` using one working feature set below:

<!-- docs-sync:runnable-examples-start -->
| Example | Feature(s) | Description |
|---------|------------|-------------|
| [adapter_jsonwebtoken](crates/uselesskey/examples/adapter_jsonwebtoken.rs) | `rsa,ecdsa,ed25519,hmac` | Sign and verify JWTs using `jsonwebtoken` crate integration |
| [adapter_rustls](crates/uselesskey/examples/adapter_rustls.rs) | `x509` | Convert X.509 fixtures into rustls `ServerConfig` / `ClientConfig` |
| [basic_ecdsa](crates/uselesskey/examples/basic_ecdsa.rs) | `ecdsa,jwk` | Generate ECDSA keypairs for P-256 and P-384 in PEM, DER, JWK |
| [basic_ed25519](crates/uselesskey/examples/basic_ed25519.rs) | `ed25519,jwk` | Generate Ed25519 keypairs in PEM, DER, and JWK formats |
| [basic_hmac](crates/uselesskey/examples/basic_hmac.rs) | `hmac,jwk` | Generate HMAC secrets for HS256, HS384, and HS512 |
| [basic_rsa](crates/uselesskey/examples/basic_rsa.rs) | `rsa,jwk` | Generate RSA keypairs in PEM, DER, and JWK formats |
| [basic_token](crates/uselesskey/examples/basic_token.rs) | `token` | Generate API key, bearer token, and OAuth access-token fixtures |
| [basic_usage](crates/uselesskey/examples/basic_usage.rs) | `ecdsa,ed25519,rsa,jwk` | All-in-one: RSA, ECDSA, and Ed25519 fixture generation |
| [deterministic](crates/uselesskey/examples/deterministic.rs) | `rsa` | Reproducible fixtures from seeds - same seed always yields the same key |
| [deterministic_mode](crates/uselesskey/examples/deterministic_mode.rs) | `rsa,ecdsa,ed25519` | Order-independent deterministic derivation guarantees |
| [jwk_generation](crates/uselesskey/examples/jwk_generation.rs) | `ecdsa,ed25519,hmac,rsa,jwk` | Build JWKs and JWKS with `JwksBuilder` across key types |
| [jwk_jwks](crates/uselesskey/examples/jwk_jwks.rs) | `ecdsa,ed25519,hmac,rsa,jwk` | JWK sets from multiple key types with metadata inspection |
| [jwks](crates/uselesskey/examples/jwks.rs) | `rsa,ecdsa,jwk` | Build a JWKS from RSA and ECDSA public keys |
| [jwks_server_mock](crates/uselesskey/examples/jwks_server_mock.rs) | `rsa,ecdsa,ed25519,jwk` | Generate a JWKS response body for a mock `/.well-known/jwks.json` endpoint |
| [jwt_rs256_jwks](crates/uselesskey/examples/jwt_rs256_jwks.rs) | `rsa,jwk` | RSA keypairs with JWK/JWKS extraction for JWT verification flows |
| [jwt_signing](crates/uselesskey/examples/jwt_signing.rs) | `rsa,jwk` | JWT signing with deterministic RSA, ECDSA, and HMAC keys (ECDSA/HMAC optional) |
| [negative_fixtures](crates/uselesskey/examples/negative_fixtures.rs) | `x509` | Intentionally invalid certificates and keys for error-path testing |
| [tempfile_paths](crates/uselesskey/examples/tempfile_paths.rs) | `rsa,ed25519` | Write key fixtures to temporary files for path-based APIs |
| [tempfiles](crates/uselesskey/examples/tempfiles.rs) | `x509` | Write X.509 cert, key, and identity PEM to temp files |
| [tls_server](crates/uselesskey/examples/tls_server.rs) | `x509` | Certificate chain generation for TLS server testing |
| [token_generation](crates/uselesskey/examples/token_generation.rs) | `token` | Realistic API keys, bearer tokens, and OAuth tokens for tests |
| [x509_certificates](crates/uselesskey/examples/x509_certificates.rs) | `x509` | Self-signed certs, cert chains, and negative X.509 fixtures |
<!-- docs-sync:runnable-examples-end -->

## Workspace Crates

`uselesskey` is a **facade crate** that re-exports from focused implementation crates.
Depend on the facade for convenience, or on individual crates to minimize compile time.

### Implementation Crates

<!-- docs-sync:workspace-crates-start -->
| Crate | Description |
|-------|-------------|
| [`uselesskey`](https://crates.io/crates/uselesskey) | Public facade — re-exports all key types and traits behind feature flags |
| [`uselesskey-core`](https://crates.io/crates/uselesskey-core) | Factory, deterministic derivation, caching, and negative-fixture helpers |
| [`uselesskey-rsa`](https://crates.io/crates/uselesskey-rsa) | RSA 2048/3072/4096 keypairs (PKCS#8, SPKI, PEM, DER) |
| [`uselesskey-ecdsa`](https://crates.io/crates/uselesskey-ecdsa) | ECDSA P-256 / P-384 keypairs |
| [`uselesskey-ed25519`](https://crates.io/crates/uselesskey-ed25519) | Ed25519 keypairs |
| [`uselesskey-hmac`](https://crates.io/crates/uselesskey-hmac) | HMAC HS256/HS384/HS512 secrets |
| [`uselesskey-ssh`](https://crates.io/crates/uselesskey-ssh) | Deterministic OpenSSH key and certificate fixtures |
| [`uselesskey-pgp`](https://crates.io/crates/uselesskey-pgp) | OpenPGP key fixtures (armored + binary keyblocks) |
| [`uselesskey-token`](https://crates.io/crates/uselesskey-token) | API key, bearer token, and OAuth access-token fixtures |
| [`uselesskey-webhook`](https://crates.io/crates/uselesskey-webhook) | Deterministic webhook fixtures for GitHub, Stripe, and Slack signature tests |
| [`uselesskey-jwk`](https://crates.io/crates/uselesskey-jwk) | Typed JWK/JWKS models and builders |
| [`uselesskey-x509`](https://crates.io/crates/uselesskey-x509) | X.509 self-signed certificates and certificate chains |
| [`uselesskey-cli`](https://crates.io/crates/uselesskey-cli) | Command-line fixture generation, bundling, and export helpers |
| [`uselesskey-test-server`](https://crates.io/crates/uselesskey-test-server) | Deterministic OIDC discovery and JWKS HTTP test server fixtures |
<!-- docs-sync:workspace-crates-end -->

### Adapter Crates

<!-- docs-sync:adapter-crates-start -->
| Crate | Description |
|-------|-------------|
| [`uselesskey-axum`](https://crates.io/crates/uselesskey-axum) | `axum` auth-test helpers with deterministic JWKS/OIDC routes |
| [`uselesskey-jsonwebtoken`](https://crates.io/crates/uselesskey-jsonwebtoken) | `jsonwebtoken` `EncodingKey` / `DecodingKey` |
| [`uselesskey-jose-openid`](https://crates.io/crates/uselesskey-jose-openid) | JOSE/OpenID-oriented native `jsonwebtoken` key conversions |
| [`uselesskey-native-tls`](https://crates.io/crates/uselesskey-native-tls) | `native-tls` `Identity` / `Certificate` conversions and connector builders |
| [`uselesskey-openssl`](https://crates.io/crates/uselesskey-openssl) | OpenSSL native types (`PKey`, `X509`) with sign/verify helpers |
| [`uselesskey-pgp-native`](https://crates.io/crates/uselesskey-pgp-native) | Native `pgp` `SignedSecretKey` / `SignedPublicKey` adapters |
| [`uselesskey-rustls`](https://crates.io/crates/uselesskey-rustls) | `rustls` `ServerConfig` / `ClientConfig` builders |
| [`uselesskey-tonic`](https://crates.io/crates/uselesskey-tonic) | `tonic::transport` TLS identity / config for gRPC |
| [`uselesskey-webpki`](https://crates.io/crates/uselesskey-webpki) | `rustls-webpki` chain verification helpers for X.509 fixtures |
| [`uselesskey-ring`](https://crates.io/crates/uselesskey-ring) | `ring` 0.17 native signing key types |
| [`uselesskey-rustcrypto`](https://crates.io/crates/uselesskey-rustcrypto) | RustCrypto native types (`rsa::RsaPrivateKey`, etc.) |
| [`uselesskey-aws-lc-rs`](https://crates.io/crates/uselesskey-aws-lc-rs) | `aws-lc-rs` native types |
<!-- docs-sync:adapter-crates-end -->

## Feature Flags

The `uselesskey` facade defaults to no features.

Extension traits by feature:
- `rsa`: `RsaFactoryExt`
- `ecdsa`: `EcdsaFactoryExt`
- `ed25519`: `Ed25519FactoryExt`
- `hmac`: `HmacFactoryExt`
- `pgp`: `PgpFactoryExt`
- `token`: `TokenFactoryExt`
- `x509`: `X509FactoryExt`

For output-family coverage and dependency implications, use the matrix below.

## Feature matrix

### Facade features (`uselesskey` crate)

<!-- docs-sync:feature-matrix-facade-start -->
| Feature | Extension Trait | Algorithms / Outputs | Implies |
|---------|----------------|---------------------|---------|
| `rsa` | `RsaFactoryExt` | RSA 2048/3072/4096 — PKCS#8, SPKI, PEM, DER | — |
| `ecdsa` | `EcdsaFactoryExt` | P-256 (ES256), P-384 (ES384) — PKCS#8, SPKI | — |
| `ed25519` | `Ed25519FactoryExt` | Ed25519 — PKCS#8, SPKI | — |
| `hmac` | `HmacFactoryExt` | HS256, HS384, HS512 | — |
| `pgp` | `PgpFactoryExt` | OpenPGP RSA 2048/3072, Ed25519 — armored, binary | — |
| `token` | `TokenFactoryExt` | API key, bearer access token, and OAuth access token | — |
| `x509` | `X509FactoryExt` | Self-signed certs, cert chains, negative certs | `rsa` |
| `jwk` | — | JWK/JWKS output for all enabled key types | — |
| `all-keys` | — | (bundle) | `rsa` `ecdsa` `ed25519` `hmac` `pgp` |
| `full` | — | (everything) | `all-keys` `token` `x509` `jwk` |
<!-- docs-sync:feature-matrix-facade-end -->

### Adapter crate key-type support

Each adapter crate has per-algorithm feature flags (`rsa`, `ecdsa`, `ed25519`, `hmac`) and an `all` convenience flag.

<!-- docs-sync:feature-matrix-adapters-start -->
| Adapter | RSA | ECDSA | Ed25519 | HMAC | X.509 / TLS | Extra features |
|---------|:---:|:-----:|:-------:|:----:|:-----------:|----------------|
| `uselesskey-jsonwebtoken` | ✓ | ✓ | ✓ | ✓ | — | — |
| `uselesskey-jose-openid` | ✓ | ✓ | ✓ | ✓ | — | — |
| `uselesskey-native-tls` | — | — | — | — | ✓ | — |
| `uselesskey-openssl` | ✓ | ✓ | ✓ | — | ✓ | `x509, all` |
| `uselesskey-pgp-native` | — | — | — | — | — | — |
| `uselesskey-ring` | ✓ | ✓ | ✓ | — | — | — |
| `uselesskey-rustcrypto` | ✓ | ✓ | ✓ | ✓ | — | — |
| `uselesskey-aws-lc-rs` | ✓ | ✓ | ✓ | — | — | `native (enables aws-lc-rs dep)` |
| `uselesskey-rustls` | ✓ | ✓ | ✓ | — | ✓ | `tls-config, rustls-ring, rustls-aws-lc-rs` |
| `uselesskey-tonic` | — | — | — | — | ✓ | — |
| `uselesskey-webpki` | — | — | — | — | ✓ | — |
<!-- docs-sync:feature-matrix-adapters-end -->

## Why this crate

### Order-independent determinism

Fixtures derive from stable identity components:

```text
seed + (domain, label, spec, variant) -> derived seed -> artifact
```

Adding new fixtures doesn't perturb existing ones. Test order doesn't matter.

### Cache-by-identity

RSA keygen is expensive. Per-factory caching by `(domain, label, spec, variant)` makes runtime generation cheap enough to replace committed fixtures.

### Shape-first outputs

Ask for shapes first: PKCS#8, SPKI, PEM, DER, JWK, JWKS, or tempfiles.
Consumers ask for artifact shapes; low-level crypto primitives are intentionally not the default output.

### Negative artifacts as first-class

Corrupt PEM, truncated DER, mismatched keys, expired certs, revoked leaves with CRLs: these are exactly the artifacts teams otherwise handcraft and commit.
`uselesskey` makes them deterministic, cheap, and disposable.

## When not to use this crate

- production key generation
- runtime certificate authority behavior
- certificate validation logic
- HSM / TPM / hardware-backed keys
- signing or verification APIs as the primary abstraction

For runtime certificate generation, reach for `rcgen` directly. For validation, use `rustls`, `x509-parser`, or the library actually responsible for verification.

## Ecosystem

Use `uselesskey` when you need **realistic test fixtures that should not live in git history**.

Reach for:

- `rcgen` when you need runtime certificate generation outside a fixture-centric workflow
- `rustls` when you need TLS runtime integration and validation
- `x509-parser` when you need parsing/inspection/validation work

## Community

- [CHANGELOG](CHANGELOG.md) — release history
- [CONTRIBUTING](CONTRIBUTING.md) — how to build, test, and add new key types
- [SECURITY](SECURITY.md) — security policy (this is a test-only crate)
- [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) — Contributor Covenant
- [SUPPORT](SUPPORT.md) — how to get help

## Stability and versioning

**Derivation stability**
Artifacts for a given `(seed, domain, label, spec, variant)` tuple are stable within the same `DerivationVersion`.
If derivation logic changes, a new derivation version is introduced instead of mutating the old one.

**Semver**
Breaking API changes bump the minor version until `1.0`, then the major version.

**MSRV**
The minimum supported Rust version is **1.92** (edition 2024).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
