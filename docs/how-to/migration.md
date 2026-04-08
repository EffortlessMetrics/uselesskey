# Migrating to `uselesskey` 0.6.0: deterministic crypto fixtures without committed blobs

This guide shows how to replace committed PEM/DER/JWK/token blobs with runtime-generated fixtures using `uselesskey` **0.6.0**.

## What this repo is for

`uselesskey` is a **test-fixture layer** for Rust projects. It is not a production crypto framework.

Use it to:
- Generate realistic fixture shapes at runtime (PKCS#8, SPKI, JWK/JWKS, X.509, OpenPGP, token shapes)
- Keep secret-like blobs out of Git history
- Get reproducible deterministic fixtures for CI and flaky test debugging
- Add negative fixtures (corrupt PEM, truncated DER, mismatch variants) without hand-crafting blobs

## Quick-start integration (Cargo)

Use `uselesskey` as a `dev-dependency`, then opt into only the fixture families you need.

```toml
[dev-dependencies]
uselesskey = { version = "0.6.0", default-features = false, features = ["rsa", "jwk"] }
```

### Minimal feature examples

```toml
# token-only tests
[dev-dependencies]
uselesskey = { version = "0.6.0", default-features = false, features = ["token"] }
```

```toml
# TLS chain + rustls adapter
[dev-dependencies]
uselesskey = { version = "0.6.0", default-features = false, features = ["x509"] }
uselesskey-rustls = { version = "0.6.0" }
```

```toml
# JWT + JOSE/OpenID style conversions
[dev-dependencies]
uselesskey = { version = "0.6.0", default-features = false, features = ["rsa", "hmac", "jwk"] }
uselesskey-jsonwebtoken = { version = "0.6.0" }
uselesskey-jose-openid = { version = "0.6.0" }
```

> Prefer adapter crates (`uselesskey-rustls`, `uselesskey-jsonwebtoken`, etc.) over broad feature bundles to keep compile and dependency surface small.

## Replace committed key files and inline secret blobs

### Before (anti-pattern): committed fixtures or inline blobs

```rust
const ISSUER_KEY_PEM: &str = include_str!("fixtures/issuer.pem");
const JWKS_JSON: &str = include_str!("fixtures/jwks.json");

#[test]
fn verify_jwt() {
    let key = parse_pem(ISSUER_KEY_PEM);
    let jwks = serde_json::from_str(JWKS_JSON).unwrap();
    // ...
}
```

### After (recommended): generated runtime fixtures

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

#[test]
fn verify_jwt() {
    let fx = Factory::deterministic_from_str("verify-jwt");
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    let key = parse_pem(issuer.private_key_pkcs8_pem());
    let jwks = issuer.public_jwks();
    // ...
}
```

## Deterministic mode: default for CI and snapshots

Use deterministic fixtures by default in CI so failures are reproducible.

```rust
use uselesskey::Factory;

pub fn fixtures() -> Factory {
    Factory::deterministic_from_env("USELESSKEY_SEED")
        .unwrap_or_else(|_| Factory::deterministic_from_str("local-fixtures"))
}
```

```yaml
# GitHub Actions
env:
  USELESSKEY_SEED: ci-stable-seed-v1
```

### Determinism rules of thumb

- Keep seed stable per suite (or per module)
- Use stable labels (`"issuer"`, `"server"`, `"client"`) as fixture identities
- Change labels intentionally when you want a different fixture
- Treat derivation output as predictable test data, never as secrets

## Common implementation patterns

### 1) JWT signing + verification

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

#[test]
fn jwt_roundtrip() {
    let fx = Factory::deterministic_from_str("jwt-roundtrip");
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    let token = sign_jwt(issuer.private_key_pkcs8_pem(), claims());
    let verified = verify_jwt(issuer.public_key_spki_pem(), &token);
    assert!(verified.is_ok());
}
```

### 2) Wrong-key rejection

```rust
#[test]
fn jwt_rejects_wrong_key() {
    let fx = Factory::deterministic_from_str("jwt-wrong-key");
    let issuer = fx.rsa("issuer", RsaSpec::rs256());
    let attacker = fx.rsa("attacker", RsaSpec::rs256());

    let token = sign_jwt(issuer.private_key_pkcs8_pem(), claims());
    assert!(verify_jwt(attacker.public_key_spki_pem(), &token).is_err());
}
```

### 3) Path-based libraries

```rust
#[test]
fn tls_key_path_integration() {
    let fx = Factory::deterministic_from_str("tls-key-path");
    let server = fx.rsa("server", RsaSpec::rs256());

    let key = server.write_private_key_pkcs8_pem().unwrap();
    let pubkey = server.write_public_key_spki_pem().unwrap();

    configure_tls(key.path(), pubkey.path());
}
```

### 4) Negative fixtures (parser hardening)

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
use uselesskey::negative::CorruptPem;

#[test]
fn parser_handles_corrupt_pem() {
    let fx = Factory::deterministic_from_str("negative-pem");
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    let bad = issuer.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(parse_pem(&bad).is_err());
}
```

## When to use random mode

Use `Factory::random()` when fixture values should vary across runs (e.g., exploration/fuzz-style tests), but keep in mind determinism is usually better for CI reproducibility.

## Migration checklist

1. Add `uselesskey` 0.6.0 to `[dev-dependencies]`
2. Enable only needed features (`rsa`, `ecdsa`, `ed25519`, `hmac`, `token`, `x509`, `pgp`, `jwk`)
3. Replace committed PEM/DER/JWK/token fixtures with `Factory` calls
4. Centralize seed strategy (`USELESSKEY_SEED` in CI)
5. Add negative fixture tests for parser/validator error paths
6. Remove fixture files from repo and ensure they are no longer referenced

## Handling existing scanner incidents

If historical commits still contain fixtures, choose one:

1. Rewrite history (cleanest, disruptive)
2. Mark false positive with explicit documentation (least disruptive, ongoing maintenance)
3. Accept incident and prevent recurrence by moving to runtime generation

`uselesskey` prevents *new* incidents by design because fixture material is generated at test runtime instead of being committed.
