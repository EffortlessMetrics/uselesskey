# uselesskey

[![Crates.io](https://img.shields.io/crates/v/uselesskey.svg)](https://crates.io/crates/uselesskey)
[![docs.rs](https://docs.rs/uselesskey/badge.svg)](https://docs.rs/uselesskey)
[![CI](https://github.com/EffortlessMetrics/uselesskey/actions/workflows/ci.yml/badge.svg)](https://github.com/EffortlessMetrics/uselesskey/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Deterministic cryptographic test fixtures for Rust — stop committing PEM/DER blobs into your repos.**

`uselesskey` is a test-fixture factory that generates cryptographic key material
and X.509 certificates at runtime. It is **not** a crypto library — it replaces
committed secret-shaped blobs with a single dev-dependency.

> **Do not use for production keys.** Deterministic keys are predictable by
> design. Even random-mode keys are intended for tests only.

## Why?

Secret scanners have changed the game for test fixtures:

| Approach | Drawback |
|----------|----------|
| Check in PEM files | Triggers GitGuardian / GitHub push protection |
| Generate keys ad-hoc | No caching → slow RSA keygen, no determinism |
| Use raw crypto crates | Boilerplate for PEM/DER encoding, no negative fixtures |

This crate replaces "security policy + docs + exceptions" with one
`dev-dependency`.

## Feature Selection

The facade default feature set is empty. A bare dependency gives you core types
like `Factory`, `Mode`, and `Seed`; enable only the fixture families you need.

Token-only consumers can stay lightweight:

```toml
[dev-dependencies]
uselesskey = { version = "0.5.0", default-features = false, features = ["token"] }
```

```rust
use uselesskey::{Factory, TokenFactoryExt, TokenSpec};

let fx = Factory::deterministic_from_str("api-key-fixtures");
let token = fx.token("svc-api", TokenSpec::api_key());

assert!(token.value().starts_with("uk_test_"));
```

## Quick Start

If you want RSA fixtures, enable `rsa` explicitly:

```toml
[dev-dependencies]
uselesskey = { version = "0.5.0", features = ["rsa"] }
```

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

let fx = Factory::random();
let rsa = fx.rsa("my-service", RsaSpec::rs256());

let private_pem = rsa.private_key_pkcs8_pem();
let public_der = rsa.public_key_spki_der();
```

### Deterministic Mode

Same seed + same label + same spec = identical output every time, regardless of
call order:

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

let fx = Factory::deterministic_from_str("my-test-seed");
let rsa = fx.rsa("issuer", RsaSpec::rs256());
```

Or read the seed from an environment variable in CI:

```rust
use uselesskey::Factory;

let fx = Factory::deterministic_from_env("USELESSKEY_SEED")
    .unwrap_or_else(|_| Factory::random());
```

## Supported Key Types

| Algorithm | Feature | Extension Trait | Spec Constructor |
|-----------|---------|-----------------|------------------|
| RSA 2048+ | `rsa` | `RsaFactoryExt` | `RsaSpec::rs256()` |
| ECDSA P-256 / P-384 | `ecdsa` | `EcdsaFactoryExt` | `EcdsaSpec::es256()` / `es384()` |
| Ed25519 | `ed25519` | `Ed25519FactoryExt` | `Ed25519Spec::new()` |
| HMAC | `hmac` | `HmacFactoryExt` | `HmacSpec::hs256()` / `hs384()` / `hs512()` |
| OpenPGP | `pgp` | `PgpFactoryExt` | `PgpSpec::rsa_2048()` / `ed25519()` |
| Tokens | `token` | `TokenFactoryExt` | `TokenSpec::api_key()` / `bearer()` / `oauth_access_token()` |
| X.509 Certs | `x509` | `X509FactoryExt` | `X509Spec::self_signed(cn)` / `ChainSpec::new(cn)` |

### Feature Flags

| Feature | Description |
|---------|-------------|
| `rsa` | RSA keypairs |
| `ecdsa` | ECDSA P-256 / P-384 keypairs |
| `ed25519` | Ed25519 keypairs |
| `hmac` | HMAC secrets |
| `pgp` | OpenPGP armored + binary keyblocks |
| `token` | API key, bearer token, OAuth access token fixtures |
| `x509` | X.509 self-signed certificates and certificate chains |
| `jwk` | JWK / JWKS output for enabled key types |
| `all-keys` | All key algorithms (`rsa` + `ecdsa` + `ed25519` + `hmac` + `pgp`) |
| `full` | Everything (`all-keys` + `token` + `x509` + `jwk`) |

The default feature set is empty.

## Output Formats

Every key type provides:

- **PKCS#8 PEM / DER** — private keys
- **SPKI PEM / DER** — public keys
- **Tempfiles** — `write_*` methods for libraries that need file paths
- **JWK / JWKS** — with the `jwk` feature

X.509 certificates additionally provide PEM / DER cert output, identity PEM
(cert + key), and chain PEM (leaf + intermediate).

## Negative Fixtures

Test error-handling paths with intentionally broken material:

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
use uselesskey::negative::CorruptPem;

let fx = Factory::random();
let rsa = fx.rsa("test", RsaSpec::rs256());

let bad_pem   = rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
let truncated = rsa.private_key_pkcs8_der_truncated(32);
let mismatch  = rsa.mismatched_public_key_spki_der();
```

X.509 chains support expired and not-yet-valid leaf/intermediate certs,
hostname mismatch, unknown CA, intermediate CA/key-usage violations, and
revoked leaf (with CRL):

```rust
use uselesskey::{Factory, X509FactoryExt, ChainSpec};

let fx = Factory::random();
let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));

let expired    = chain.expired_leaf();
let future     = chain.not_yet_valid_leaf();
let wrong_host = chain.hostname_mismatch("wrong.example.com");
let unknown_ca = chain.unknown_ca();
let bad_ca     = chain.intermediate_not_ca();
let bad_usage  = chain.intermediate_wrong_key_usage();
let revoked    = chain.revoked_leaf();
```

## Adapter Crates

Adapter crates bridge uselesskey fixtures to third-party library types. They are
separate crates (not features) to avoid coupling versioning.

| Crate | Provides |
|-------|----------|
| [`uselesskey-jsonwebtoken`](https://crates.io/crates/uselesskey-jsonwebtoken) | `jsonwebtoken::EncodingKey` / `DecodingKey` |
| [`uselesskey-rustls`](https://crates.io/crates/uselesskey-rustls) | `rustls` `ServerConfig` / `ClientConfig` builders |
| [`uselesskey-tonic`](https://crates.io/crates/uselesskey-tonic) | `tonic::transport` TLS identity / config for gRPC |
| [`uselesskey-ring`](https://crates.io/crates/uselesskey-ring) | `ring` 0.17 native signing key types |
| [`uselesskey-rustcrypto`](https://crates.io/crates/uselesskey-rustcrypto) | RustCrypto native types (`rsa::RsaPrivateKey`, etc.) |
| [`uselesskey-aws-lc-rs`](https://crates.io/crates/uselesskey-aws-lc-rs) | `aws-lc-rs` native types |

## Microcrate Architecture

`uselesskey` is a **facade crate** that re-exports from a family of focused
crates. If you only need one key type and want to minimize compile time, depend
on the implementation crate directly:

| Crate | Purpose |
|-------|---------|
| [`uselesskey-core`](https://crates.io/crates/uselesskey-core) | Factory, derivation, caching |
| [`uselesskey-rsa`](https://crates.io/crates/uselesskey-rsa) | RSA keypairs |
| [`uselesskey-ecdsa`](https://crates.io/crates/uselesskey-ecdsa) | ECDSA P-256 / P-384 |
| [`uselesskey-ed25519`](https://crates.io/crates/uselesskey-ed25519) | Ed25519 |
| [`uselesskey-hmac`](https://crates.io/crates/uselesskey-hmac) | HMAC secrets |
| [`uselesskey-x509`](https://crates.io/crates/uselesskey-x509) | X.509 certificates |

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.
