# uselesskey

[![CI](https://github.com/EffortlessMetrics/uselesskey/actions/workflows/ci.yml/badge.svg)](https://github.com/EffortlessMetrics/uselesskey/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/uselesskey.svg)](https://crates.io/crates/uselesskey)
[![docs.rs](https://docs.rs/uselesskey/badge.svg)](https://docs.rs/uselesskey)
[![MSRV](https://img.shields.io/badge/MSRV-1.92-blue.svg)](https://doc.rust-lang.org/cargo/reference/manifest.html#the-rust-version-field)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

*Deterministic cryptographic test fixtures for Rust.*

**Stop committing PEM/DER/JWK blobs into your repos.**

A test-fixture factory that generates cryptographic key material and X.509 certificates at runtime. Not a crypto library.

## The Problem

Secret scanners have changed the game for test fixtures:

- **GitGuardian** scans each commit in a PR. "Add then remove" still triggers incidents.
- **GitHub push protection** blocks pushes until the secret is removed from all commits.
- Path ignores exist but require ongoing maintenance and documentation.

Even fake keys that look real cause friction. This crate replaces "security policy + docs + exceptions" with one dev-dependency.

> **Do not use for production keys.** Deterministic keys are predictable by design. Even random-mode keys are intended for tests only.

## Why Not Just...

| Approach | Drawback |
|----------|----------|
| Check in PEM files | Triggers GitGuardian/GitHub push protection |
| Generate keys ad-hoc in tests | No caching, slow RSA keygen, no determinism |
| Use raw crypto crates directly | Boilerplate for PEM/DER encoding, no negative fixtures |
| Use `rcgen` directly | Not test-fixture-focused; no deterministic mode, no negative fixtures |

## What You Get

**Algorithms:**
- RSA (2048, 3072, 4096 bits)
- ECDSA (P-256, P-384)
- Ed25519
- HMAC (HS256, HS384, HS512)
- OpenPGP (RSA 2048/3072, Ed25519)
- Token fixtures (API key, bearer, OAuth access token/JWT shape)

**Output formats:**
- PKCS#8 PEM/DER (private keys)
- SPKI PEM/DER (public keys)
- OpenPGP armored and binary keyblocks (with `pgp` feature)
- JWK/JWKS (with `jwk` feature)
- Tempfiles (for libraries that need paths)
- X.509 self-signed certificates and certificate chains (with `x509` feature)

**Negative fixtures:**
- Corrupt PEM (bad base64, wrong headers, truncated)
- Truncated DER
- Mismatched keypairs (valid public key that doesn't match the private key)
- X.509: expired leaf/intermediate, hostname mismatch, unknown CA, revoked leaf (with CRL)

## Quick Start

Add to `Cargo.toml`:

```toml
[dev-dependencies]
uselesskey = "0.3"
```

Generate keys:

```rust
use uselesskey::{Factory, Seed, RsaSpec, RsaFactoryExt};

// Random mode (different keys each run)
let fx = Factory::random();

// Deterministic mode (stable keys from seed)
let seed = Seed::from_env_value("my-test-seed").unwrap();
let fx = Factory::deterministic(seed);

// Or fall back to random if env var not set
let fx = Factory::deterministic_from_env("USELESSKEY_SEED")
    .unwrap_or_else(|_| Factory::random());

// Generate RSA keypair
let rsa = fx.rsa("issuer", RsaSpec::rs256());

let pkcs8_pem = rsa.private_key_pkcs8_pem();
let spki_der = rsa.public_key_spki_der();
```

### JWK / JWKS

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

Self-signed certificates for simple TLS tests:

```rust
use uselesskey::{Factory, X509FactoryExt, X509Spec};

let fx = Factory::random();
let cert = fx.x509_self_signed("my-service", X509Spec::self_signed("test.example.com"));

let cert_pem = cert.cert_pem();
let key_pem = cert.private_key_pkcs8_pem();
```

Three-level certificate chains (root CA → intermediate CA → leaf):

```rust
use uselesskey::{Factory, X509FactoryExt, ChainSpec};

let fx = Factory::random();
let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

// Standard TLS server chain (leaf + intermediate, no root)
let chain_pem = chain.chain_pem();

// Individual certs for custom setups
let root_pem = chain.root_cert_pem();
let leaf_key = chain.leaf_private_key_pkcs8_pem();
```

### X.509 Negative Fixtures

Generate intentionally invalid certificates for testing error-handling paths:

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

### Negative Fixtures (Keys)

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};
use uselesskey::negative::CorruptPem;

let fx = Factory::random();
let rsa = fx.rsa("issuer", RsaSpec::rs256());

let bad_pem = rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
let truncated = rsa.private_key_pkcs8_der_truncated(32);
let mismatched_pub = rsa.mismatched_public_key_spki_der();
```

### Token Fixtures

Generate realistic token-shaped fixtures without committing token blobs:

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

## Adapter Examples

Adapter crates bridge uselesskey fixtures to third-party library types. They are separate crates (not features) to avoid coupling versioning. See the [Workspace Crates](#workspace-crates) section for the full list.

### TLS Config Builders (uselesskey-rustls)

With the `tls-config` feature, build rustls configs in one line:

```toml
[dev-dependencies]
uselesskey-rustls = { version = "0.3", features = ["tls-config", "rustls-ring"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_x509::{X509FactoryExt, ChainSpec};
use uselesskey_rustls::{RustlsServerConfigExt, RustlsClientConfigExt};

let fx = Factory::random();
let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

let server_config = chain.server_config_rustls();   // ServerConfig (no client auth)
let client_config = chain.client_config_rustls();    // ClientConfig (trusts root CA)
```

### ring Signing Keys (uselesskey-ring)

```toml
[dev-dependencies]
uselesskey-ring = { version = "0.3", features = ["all"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_ring::RingRsaKeyPairExt;

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let ring_kp = rsa.rsa_key_pair_ring();  // ring::rsa::KeyPair
```

### RustCrypto Types (uselesskey-rustcrypto)

```toml
[dev-dependencies]
uselesskey-rustcrypto = { version = "0.3", features = ["all"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_rustcrypto::RustCryptoRsaExt;

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let rsa_pk = rsa.rsa_private_key(); // rsa::RsaPrivateKey
```

### aws-lc-rs Types (uselesskey-aws-lc-rs)

```toml
[dev-dependencies]
uselesskey-aws-lc-rs = { version = "0.3", features = ["native", "all"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let lc_kp = rsa.rsa_key_pair_aws_lc_rs();  // aws_lc_rs::rsa::KeyPair
```

### gRPC TLS (uselesskey-tonic)

```toml
[dev-dependencies]
uselesskey-tonic = "0.3"
```

```rust
use uselesskey_core::Factory;
use uselesskey_x509::{X509FactoryExt, ChainSpec};
use uselesskey_tonic::{TonicClientTlsExt, TonicServerTlsExt};

let fx = Factory::random();
let chain = fx.x509_chain("grpc", ChainSpec::new("test.example.com"));

let server_tls = chain.server_tls_config_tonic();
let client_tls = chain.client_tls_config_tonic("test.example.com");
```

## Runnable Examples

The [`crates/uselesskey/examples/`](crates/uselesskey/examples/) directory contains standalone programs you can run with `cargo run -p uselesskey --example`:

| Example | Description |
|---------|-------------|
| [`adapter_jsonwebtoken`](crates/uselesskey/examples/adapter_jsonwebtoken.rs) | Sign and verify JWTs using `jsonwebtoken` crate integration |
| [`adapter_rustls`](crates/uselesskey/examples/adapter_rustls.rs) | Convert X.509 fixtures into rustls `ServerConfig` / `ClientConfig` |
| [`basic_ecdsa`](crates/uselesskey/examples/basic_ecdsa.rs) | Generate ECDSA keypairs for P-256 and P-384 in PEM, DER, JWK |
| [`basic_ed25519`](crates/uselesskey/examples/basic_ed25519.rs) | Generate Ed25519 keypairs in PEM, DER, and JWK formats |
| [`basic_hmac`](crates/uselesskey/examples/basic_hmac.rs) | Generate HMAC secrets for HS256, HS384, and HS512 |
| [`basic_rsa`](crates/uselesskey/examples/basic_rsa.rs) | Generate RSA keypairs in PEM, DER, and JWK formats |
| [`basic_token`](crates/uselesskey/examples/basic_token.rs) | Generate API key, bearer, and OAuth access-token fixtures |
| [`basic_usage`](crates/uselesskey/examples/basic_usage.rs) | All-in-one: RSA, ECDSA, and Ed25519 fixture generation |
| [`deterministic`](crates/uselesskey/examples/deterministic.rs) | Reproducible fixtures from seeds — same seed always yields same key |
| [`deterministic_mode`](crates/uselesskey/examples/deterministic_mode.rs) | Order-independent deterministic derivation guarantees |
| [`jwk_generation`](crates/uselesskey/examples/jwk_generation.rs) | Build JWKs and JWKS with `JwksBuilder` across key types |
| [`jwk_jwks`](crates/uselesskey/examples/jwk_jwks.rs) | JWK Sets from multiple key types with metadata inspection |
| [`jwks`](crates/uselesskey/examples/jwks.rs) | Build a JWKS from RSA and ECDSA public keys |
| [`jwks_server_mock`](crates/uselesskey/examples/jwks_server_mock.rs) | Generate a JWKS response body for a mock `/.well-known/jwks.json` endpoint |
| [`jwt_rs256_jwks`](crates/uselesskey/examples/jwt_rs256_jwks.rs) | RSA keypairs with JWK/JWKS extraction for JWT verification flows |
| [`jwt_signing`](crates/uselesskey/examples/jwt_signing.rs) | JWT signing with deterministic RSA, ECDSA, and HMAC keys |
| [`negative_fixtures`](crates/uselesskey/examples/negative_fixtures.rs) | Intentionally invalid certificates and keys for error-path testing |
| [`tempfile_paths`](crates/uselesskey/examples/tempfile_paths.rs) | Write key fixtures to temporary files for path-based APIs |
| [`tempfiles`](crates/uselesskey/examples/tempfiles.rs) | Write X.509 cert, key, and identity PEM to temp files |
| [`tls_server`](crates/uselesskey/examples/tls_server.rs) | Certificate chain generation for TLS server testing |
| [`token_generation`](crates/uselesskey/examples/token_generation.rs) | Realistic API keys, bearer tokens, and OAuth tokens for tests |
| [`x509_certificates`](crates/uselesskey/examples/x509_certificates.rs) | Self-signed certs, cert chains, and negative X.509 fixtures |

## Workspace Crates

`uselesskey` is a **facade crate** that re-exports from focused implementation crates.
Depend on the facade for convenience, or on individual crates to minimize compile time.

### Implementation Crates

| Crate | Description |
|-------|-------------|
| [`uselesskey`](https://crates.io/crates/uselesskey) | Public facade — re-exports all key types and traits behind feature flags |
| [`uselesskey-core`](https://crates.io/crates/uselesskey-core) | Factory, deterministic derivation, caching, and negative-fixture helpers |
| [`uselesskey-rsa`](https://crates.io/crates/uselesskey-rsa) | RSA 2048/3072/4096 keypairs (PKCS#8, SPKI, PEM, DER) |
| [`uselesskey-ecdsa`](https://crates.io/crates/uselesskey-ecdsa) | ECDSA P-256 / P-384 keypairs |
| [`uselesskey-ed25519`](https://crates.io/crates/uselesskey-ed25519) | Ed25519 keypairs |
| [`uselesskey-hmac`](https://crates.io/crates/uselesskey-hmac) | HMAC HS256/HS384/HS512 secrets |
| [`uselesskey-pgp`](https://crates.io/crates/uselesskey-pgp) | OpenPGP key fixtures (armored + binary keyblocks) |
| [`uselesskey-token`](https://crates.io/crates/uselesskey-token) | API key, bearer token, and OAuth access-token fixtures |
| [`uselesskey-jwk`](https://crates.io/crates/uselesskey-jwk) | Typed JWK/JWKS models and builders |
| [`uselesskey-x509`](https://crates.io/crates/uselesskey-x509) | X.509 self-signed certificates and certificate chains |

### Adapter Crates

| Crate | Integrates with |
|-------|-----------------|
| [`uselesskey-jsonwebtoken`](https://crates.io/crates/uselesskey-jsonwebtoken) | `jsonwebtoken` `EncodingKey` / `DecodingKey` |
| [`uselesskey-rustls`](https://crates.io/crates/uselesskey-rustls) | `rustls` `ServerConfig` / `ClientConfig` builders |
| [`uselesskey-tonic`](https://crates.io/crates/uselesskey-tonic) | `tonic::transport` TLS identity / config for gRPC |
| [`uselesskey-ring`](https://crates.io/crates/uselesskey-ring) | `ring` 0.17 native signing key types |
| [`uselesskey-rustcrypto`](https://crates.io/crates/uselesskey-rustcrypto) | RustCrypto native types (`rsa::RsaPrivateKey`, etc.) |
| [`uselesskey-aws-lc-rs`](https://crates.io/crates/uselesskey-aws-lc-rs) | `aws-lc-rs` native types |

## Feature Flags

| Feature | Description |
|---------|-------------|
| `rsa` | RSA keypairs (default) |
| `ecdsa` | ECDSA P-256/P-384 keypairs |
| `ed25519` | Ed25519 keypairs |
| `hmac` | HMAC secrets |
| `pgp` | OpenPGP keypairs (armored + binary keyblocks) |
| `token` | API key, bearer token, and OAuth access token fixtures |
| `x509` | X.509 certificate generation (implies `rsa`) |
| `jwk` | JWK/JWKS output for enabled key types |
| `all-keys` | All key algorithms (`rsa` + `ecdsa` + `ed25519` + `hmac` + `pgp`) |
| `full` | Everything (`all-keys` + `token` + `x509` + `jwk`) |

Extension traits by feature:
- `rsa`: `RsaFactoryExt`
- `ecdsa`: `EcdsaFactoryExt`
- `ed25519`: `Ed25519FactoryExt`
- `hmac`: `HmacFactoryExt`
- `pgp`: `PgpFactoryExt`
- `token`: `TokenFactoryExt`
- `x509`: `X509FactoryExt`

## Feature Matrix

### Facade features (`uselesskey` crate)

| Feature | Extension Trait | Algorithms / Outputs | Implies |
|---------|----------------|---------------------|---------|
| `rsa` *(default)* | `RsaFactoryExt` | RSA 2048/3072/4096 — PKCS#8, SPKI, PEM, DER | — |
| `ecdsa` | `EcdsaFactoryExt` | P-256 (ES256), P-384 (ES384) — PKCS#8, SPKI | — |
| `ed25519` | `Ed25519FactoryExt` | Ed25519 — PKCS#8, SPKI | — |
| `hmac` | `HmacFactoryExt` | HS256, HS384, HS512 | — |
| `pgp` | `PgpFactoryExt` | OpenPGP RSA 2048/3072, Ed25519 — armored, binary | — |
| `token` | `TokenFactoryExt` | API key, bearer, OAuth access token | — |
| `x509` | `X509FactoryExt` | Self-signed certs, cert chains, negative certs | `rsa` |
| `jwk` | — | JWK/JWKS output for all enabled key types | — |
| `all-keys` | — | *(bundle)* | `rsa` `ecdsa` `ed25519` `hmac` `pgp` |
| `full` | — | *(everything)* | `all-keys` `token` `x509` `jwk` |

### Adapter crate key-type support

Each adapter crate has per-algorithm feature flags (`rsa`, `ecdsa`, `ed25519`, `hmac`) and an `all` convenience flag.

| Adapter | RSA | ECDSA | Ed25519 | HMAC | X.509 / TLS | Extra features |
|---------|:---:|:-----:|:-------:|:----:|:-----------:|----------------|
| `uselesskey-jsonwebtoken` | ✓ | ✓ | ✓ | ✓ | — | — |
| `uselesskey-ring` | ✓ | ✓ | ✓ | — | — | — |
| `uselesskey-rustcrypto` | ✓ | ✓ | ✓ | ✓ | — | — |
| `uselesskey-aws-lc-rs` | ✓ | ✓ | ✓ | — | — | `native` (enables aws-lc-rs dep) |
| `uselesskey-rustls` | ✓ | ✓ | ✓ | — | ✓ | `tls-config`, `rustls-ring`, `rustls-aws-lc-rs` |
| `uselesskey-tonic` | — | — | — | — | ✓ | — |

## Why This Crate?

### Order-independent determinism

`seed + (domain, label, spec, variant) -> derived seed -> artifact`

Adding new fixtures doesn't perturb existing ones. Test order doesn't matter.

### Cache-by-identity

RSA keygen is expensive. Per-process caching by `(domain, label, spec, variant)` makes runtime generation cheap enough to replace committed fixtures.

### Shape-first outputs

Ask for PKCS#8/SPKI/JWK, not crypto primitives. Users shouldn't need to know which crate does the encoding.

### Negative fixtures first-class

Corrupt PEM, truncated DER, mismatched keys, expired certs, revoked leaves with CRLs. These are annoying to produce manually, which is why teams commit them. This crate makes them cheap and ephemeral.

### When NOT to use this crate

- Production key generation or certificate management
- Certificate validation logic (use `rustls`, `x509-parser`)
- Runtime CA operations (use `rcgen` directly)

## Ecosystem

Use uselesskey when you need **test fixtures that don't trip secret scanners**. If you need runtime certificate generation for production (e.g., an internal CA), reach for [`rcgen`](https://docs.rs/rcgen) directly. If you need certificate validation logic, see [`rustls`](https://docs.rs/rustls) or [`x509-parser`](https://docs.rs/x509-parser).

## Community

- [CHANGELOG](CHANGELOG.md) — release history
- [CONTRIBUTING](CONTRIBUTING.md) — how to build, test, and add new key types
- [SECURITY](SECURITY.md) — security policy (this is a test-only crate)
- [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) — Contributor Covenant
- [SUPPORT](SUPPORT.md) — how to get help

## Stability & Versioning

**Derivation stability:** Artifacts generated with a given `(seed, domain, label, spec, variant)` tuple are stable within the same `DerivationVersion`. We will never change `V1` output; if derivation logic changes, a new version (e.g., `V2`) will be introduced.

**MSRV:** The minimum supported Rust version is **1.92** (edition 2024).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
