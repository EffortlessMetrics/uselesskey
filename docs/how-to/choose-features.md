# Choosing `uselesskey` feature sets

Use this page when you are deciding which feature flags to enable first.

`uselesskey` is a facade crate with an empty default feature set. Start from one goal and add only what tests need.

## I need keys

- Use `rsa` for RSA fixtures (2048/3072/4096).
- Add `ecdsa` for P-256 / P-384.
- Add `ed25519` for Ed25519 keypairs.
- Add `hmac` for HS256/HS384/HS512 fixtures.
- Add `pgp` for OpenPGP armored/binary artifacts.

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa", "ecdsa", "ed25519", "hmac", "pgp"] }
```

If you need every key family, use `all-keys`.

## I need JWK / JWKS

- Add `jwk` plus the key families you want represented in the JWK outputs.
- Keep `jwk` off when all you need is PEM/DER/private-key text.

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["rsa", "jwk"] }
```

## I need X.509 / TLS

- Add `x509` for self-signed certs and certificate chains.
- Add `uselesskey-rustls` (with `tls-config`) when you need rustls-native config builders.
- Add `uselesskey-tonic` when you need gRPC TLS examples.

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["x509"] }
uselesskey-rustls = { version = "0.5.1", features = ["tls-config", "rustls-ring"] }
```

## I need token shapes only

- Add `token` (and disable default features if you only want token fixtures).

```toml
[dev-dependencies]
uselesskey = { version = "0.5.1", default-features = false, features = ["token"] }
```

## When you want fewer dependencies

- Prefer the facade for speed and convenience.
- Prefer direct leaf crates when dependency shape is more important than convenience.

