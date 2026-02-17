# uselesskey-token

Token-shaped fixtures for tests, built on `uselesskey-core`.

Generates deterministic or random token strings so authorization code paths can be tested without committing secret-looking blobs.

## What It Provides

- API-key style tokens: `uk_test_<base62>`
- Opaque bearer tokens: base64url data
- OAuth access tokens in JWT shape: `header.payload.signature`

## Example

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

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
