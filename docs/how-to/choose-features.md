# Choosing `uselesskey` feature sets

Use this page when you are deciding which feature flags to enable first.

`uselesskey` is a facade crate with an empty default feature set. Start from one goal and add only what tests need.

## Pick the lane first

Use this decision table before choosing individual feature flags.

| Need | Lane |
|----------|----------|
| entropy / scanner-shape only | `uselesskey-entropy` or facade `features = ["entropy"]` |
| JWT / bearer / API-token shapes only | `uselesskey-token` or facade `features = ["token"]` |
| valid runtime crypto semantics | leaf crates such as `uselesskey-rsa`, `uselesskey-x509`, `uselesskey-ssh` |
| build-time materialized fixtures | `uselesskey-cli materialize` + `verify` |

For a short workflow-oriented version, see `docs/how-to/choose-lane.md`.

## I need keys

- Use `rsa` for RSA fixtures (2048/3072/4096).
- Add `ecdsa` for P-256 / P-384.
- Add `ed25519` for Ed25519 keypairs.
- Add `hmac` for HS256/HS384/HS512 fixtures.
- Add `pgp` for OpenPGP armored/binary artifacts.

## I need high-entropy bytes only

- Add `entropy` when tests only need deterministic byte buffers.
- Prefer this over a key-generating lane when the test does not need crypto semantics.

<!-- docs-sync:dependency-snippets-start -->
Dependency snippets:
- **Quick start (RSA)**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.6.0", features = ["rsa"] }
  ```


- **Token-only**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.6.0", default-features = false, features = ["token"] }
  ```


- **JWT/JWK**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.6.0", features = ["rsa", "jwk"] }
  ```


- **X.509 + rustls**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.6.0", features = ["x509"] }
  uselesskey-rustls = { version = "0.6.0", features = ["tls-config", "rustls-ring"] }
  ```


- **jsonwebtoken adapter**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.6.0", features = ["rsa", "ecdsa", "ed25519", "hmac"] }
  uselesskey-jsonwebtoken = { version = "0.6.0" }
  ```


- **JOSE/OpenID adapter**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.6.0", features = ["rsa", "ecdsa", "ed25519", "hmac"] }
  uselesskey-jose-openid = { version = "0.6.0" }
  ```


- **pgp-native adapter**
  ```toml
  [dev-dependencies]
  uselesskey = { version = "0.6.0", features = ["pgp"] }
  uselesskey-pgp-native = { version = "0.6.0" }
  ```
<!-- docs-sync:dependency-snippets-end -->

If you need every key family, use `all-keys`.

## I need JWK / JWKS

- Add `jwk` plus the key families you want represented in the JWK outputs.
- Keep `jwk` off when all you need is PEM/DER/private-key text.

## I need X.509 / TLS

- Add `x509` for self-signed certs and certificate chains.
- Add `uselesskey-rustls` (with `tls-config`) when you need rustls-native config builders.
- Add `uselesskey-tonic` when you need gRPC TLS examples.

## I need token shapes only

- Add `token` (and disable default features if you only want token fixtures).

## I need valid runtime crypto semantics

- Use the leaf crate for the actual fixture family you need when local economics matter more than facade convenience.
- Reach for `uselesskey-rsa`, `uselesskey-x509`, `uselesskey-ssh`, or other focused crates before `full`.

## I need static-like local fixtures

- Use `uselesskey-cli materialize` when tests want `OUT_DIR` or `include_bytes!`
  instead of runtime generation.
- Use `uselesskey-cli verify` in CI to prove generated outputs still match the
  manifest.
- If `build.rs` calls the library directly, use:
  `uselesskey-cli = { version = "0.6.0", default-features = false }`
  for the common shape-only path.
- Add `features = ["rsa-materialize"]` only when the build-time path needs RSA
  PKCS#8 fixtures.
- See `crates/materialize-shape-buildrs-example/` for the common build-time
  pattern and `crates/materialize-buildrs-example/` for the specialized RSA
  pattern.

## Minimal runnable commands

<!-- docs-sync:minimal-example-commands-start -->
| Scenario | Minimal command | Description |
|----------|------------------|-------------|
| RSA + JWK | `cargo run -p uselesskey --example basic_rsa --no-default-features --features rsa,jwk` | Generate RSA fixtures and JWK output. |
| Token fixtures | `cargo run -p uselesskey --example token_generation --no-default-features --features token` | Emit API key and bearer/OAuth token shapes. |
| X.509 + rustls | `cargo run -p uselesskey --example adapter_rustls --no-default-features --features x509` | Build rustls configs from generated cert fixtures. |
<!-- docs-sync:minimal-example-commands-end -->

## When you want fewer dependencies

- Prefer the facade for speed and convenience.
- Prefer direct leaf crates when dependency shape is more important than convenience.
- For entropy-only tests, `uselesskey-entropy` is the narrowest public lane.
