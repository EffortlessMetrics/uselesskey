# uselesskey-jose-openid

Narrow conversion helpers from `uselesskey` fixtures to JOSE/OpenID-native key types.

## Feature support

| Feature | Source type | Native type conversion |
|---------|-------------|------------------------|
| `rsa` | `uselesskey-rsa` | `jsonwebtoken::EncodingKey`, `jsonwebtoken::DecodingKey` |
| `ecdsa` | `uselesskey-ecdsa` | `jsonwebtoken::EncodingKey`, `jsonwebtoken::DecodingKey` |
| `ed25519` | `uselesskey-ed25519` | `jsonwebtoken::EncodingKey`, `jsonwebtoken::DecodingKey` |
| `hmac` | `uselesskey-hmac` | `jsonwebtoken::EncodingKey`, `jsonwebtoken::DecodingKey` |
| `all` | - | Enables all above feature-gated conversions |

## Example

```rust
use uselesskey::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_jose_openid::JoseOpenIdKeyExt;
use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
}

let fx = Factory::random();
let key = fx.ecdsa("issuer", EcdsaSpec::es256());

let claims = Claims { sub: "alice".into() };
let token = encode(&Header::new(Algorithm::ES256), &claims, &key.encoding_key()).unwrap();
let result = decode::<Claims>(&token, &key.decoding_key(), &Validation::new(Algorithm::ES256)).unwrap();

assert_eq!(result.claims.sub, "alice");
```

## Crate-specific tests

- one round-trip smoke test
- one integration-style verification test for mismatched signing/verification keys

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT), at your option.
