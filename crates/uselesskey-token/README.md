# uselesskey-token

Token fixtures for tests, built on `uselesskey-core`.

Generates deterministic or random token-shaped strings so you can test
authorization paths without committing secret-looking blobs.

## What it provides

- API key style tokens (`uk_test_<base62>`)
- Opaque bearer tokens (base64url)
- OAuth access tokens in JWT shape (`header.payload.signature`)

## Example

```rust
use uselesskey_core::{Factory, Seed};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

let fx = Factory::deterministic(Seed::from_env_value("token-seed").unwrap());

let api_key = fx.token("billing", TokenSpec::api_key());
let bearer = fx.token("gateway", TokenSpec::bearer());
let oauth = fx.token("issuer", TokenSpec::oauth_access_token());

assert!(api_key.value().starts_with("uk_test_"));
assert!(bearer.authorization_header().starts_with("Bearer "));
assert_eq!(oauth.value().split('.').count(), 3);
```
