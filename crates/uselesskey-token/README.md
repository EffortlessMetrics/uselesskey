# uselesskey-token

[![Crates.io](https://img.shields.io/crates/v/uselesskey-token.svg)](https://crates.io/crates/uselesskey-token)
[![docs.rs](https://docs.rs/uselesskey-token/badge.svg)](https://docs.rs/uselesskey-token)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Token-shaped fixtures for tests, built on `uselesskey-core`.

Generates deterministic or random token strings so authorization code paths can
be tested without committing secret-looking blobs.

Part of the [`uselesskey`](https://crates.io/crates/uselesskey) workspace. Use
the facade crate for the simplest experience, or depend on this crate directly
for minimal compile time.

## What It Provides

- API-key style tokens: `uk_test_<base62>`
- Opaque bearer tokens: base64url data
- OAuth access tokens in JWT shape: `header.payload.signature`

## Usage

```rust
use uselesskey_core::Factory;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

let fx = Factory::random();

let api_key = fx.token("billing", TokenSpec::api_key());
let bearer = fx.token("gateway", TokenSpec::bearer());
let oauth = fx.token("issuer", TokenSpec::oauth_access_token());

assert!(api_key.value().starts_with("uk_test_"));
assert!(bearer.authorization_header().starts_with("Bearer "));
assert_eq!(oauth.value().split('.').count(), 3);
```

### Deterministic Mode

```rust
use uselesskey_core::{Factory, Seed};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

let seed = Seed::from_env_value("test-seed").unwrap();
let fx = Factory::deterministic(seed);

// Same seed + label + spec = same token
let t1 = fx.token("billing", TokenSpec::api_key());
let t2 = fx.token("billing", TokenSpec::api_key());
assert_eq!(t1.value(), t2.value());
```

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
