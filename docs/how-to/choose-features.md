# Choosing `uselesskey` feature sets

Use this page when you are deciding which feature flags to enable first.

`uselesskey` is a facade crate with an empty default feature set. Start from one goal and add only what tests need.

## I need keys

- Use `rsa` for RSA fixtures (2048/3072/4096).
- Add `ecdsa` for P-256 / P-384.
- Add `ed25519` for Ed25519 keypairs.
- Add `hmac` for HS256/HS384/HS512 fixtures.
- Add `pgp` for OpenPGP armored/binary artifacts.

<!-- docs-sync:feature-choice-snippets-start -->
### All key families

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa", "ecdsa", "ed25519", "hmac", "pgp"] }
```

Minimal example command:

```bash
cargo run -p uselesskey --example basic_usage --no-default-features --features rsa,ecdsa,ed25519,jwk
```

### JWT/JWK

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa", "jwk"] }
```

Minimal example command:

```bash
cargo run -p uselesskey --example jwt_rs256_jwks --no-default-features --features rsa,jwk
```

### X.509 + rustls

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["x509"] }
uselesskey-rustls = { version = "0.5.1", features = ["tls-config", "rustls-ring"] }
```

Minimal example command:

```bash
cargo run -p uselesskey --example adapter_rustls --no-default-features --features x509
```

### Token-only

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", default-features = false, features = ["token"] }
```

Minimal example command:

```bash
cargo run -p uselesskey --example basic_token --no-default-features --features token
```
<!-- docs-sync:feature-choice-snippets-end -->

## When you want fewer dependencies

- Prefer the facade for speed and convenience.
- Prefer direct leaf crates when dependency shape is more important than convenience.
