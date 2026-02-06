# uselesskey

**Stop committing PEM/DER/JWK blobs into your repos.**

A test-fixture library that generates cryptographic key material at runtime. Not a crypto library.

**MSRV:** Rust 1.92

## The Problem

Secret scanners have changed the game for test fixtures:

- **GitGuardian** scans each commit in a PR. "Add then remove" still triggers incidents.
- **GitHub push protection** blocks pushes until the secret is removed from all commits.
- Path ignores exist but require ongoing maintenance and documentation.

Even fake keys that look real cause friction. This crate replaces "security policy + docs + exceptions" with one dev-dependency.

> **Do not use for production keys.** Deterministic keys are predictable by design. Even random-mode keys are intended for tests only.

## What You Get

**Algorithms:**
- RSA (2048, 3072, 4096 bits)
- ECDSA (P-256, P-384)
- Ed25519
- HMAC (HS256, HS384, HS512)

**Output formats:**
- PKCS#8 PEM/DER (private keys)
- SPKI PEM/DER (public keys)
- JWK/JWKS (with `jwk` feature)
- Tempfiles (for libraries that need paths)
- X.509 certificates (with `x509` feature)

**Negative fixtures:**
- Corrupt PEM (bad base64, wrong headers, truncated)
- Truncated DER
- Mismatched keypairs (valid public key that doesn't match the private key)

## Quick Start

Add to `Cargo.toml`:

```toml
[dev-dependencies]
uselesskey = "0.1"
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

### Negative Fixtures

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};
use uselesskey::negative::CorruptPem;

let fx = Factory::random();
let rsa = fx.rsa("issuer", RsaSpec::rs256());

let bad_pem = rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
let truncated = rsa.private_key_pkcs8_der_truncated(32);
let mismatched_pub = rsa.mismatched_public_key_spki_der();
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `rsa` | RSA keypairs (default) |
| `ecdsa` | ECDSA P-256/P-384 keypairs |
| `ed25519` | Ed25519 keypairs |
| `hmac` | HMAC secrets |
| `x509` | X.509 certificate generation (implies `rsa`) |
| `jwk` | JWK/JWKS output for enabled key types |
| `all-keys` | All key algorithms (`rsa` + `ecdsa` + `ed25519` + `hmac`) |
| `full` | Everything (`all-keys` + `x509` + `jwk`) |

Extension traits by feature:
- `rsa`: `RsaFactoryExt`
- `ecdsa`: `EcdsaFactoryExt`
- `ed25519`: `Ed25519FactoryExt`
- `hmac`: `HmacFactoryExt`
- `x509`: `X509FactoryExt`

## Why This Crate?

### Order-independent determinism

`seed + (domain, label, spec, variant) -> derived seed -> artifact`

Adding new fixtures doesn't perturb existing ones. Test order doesn't matter.

### Cache-by-identity

RSA keygen is expensive. Per-process caching by `(domain, label, spec, variant)` makes runtime generation cheap enough to replace committed fixtures.

### Shape-first outputs

Ask for PKCS#8/SPKI/JWK, not crypto primitives. Users shouldn't need to know which crate does the encoding.

### Negative fixtures first-class

Corrupt PEM, truncated DER, mismatched keys. These are annoying to produce manually, which is why teams commit them. This crate makes them cheap and ephemeral.

## License

Licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
