# uselesskey-jsonwebtoken

`jsonwebtoken` adapter traits for `uselesskey` fixtures.

Implements `JwtKeyExt` so fixture types return `jsonwebtoken::EncodingKey` and `jsonwebtoken::DecodingKey` directly.

## Features

| Feature | Description |
|---------|-------------|
| `rsa` | RSA keypairs (RS256/RS384/RS512) |
| `ecdsa` | ECDSA keypairs (ES256/ES384) |
| `ed25519` | Ed25519 keypairs (EdDSA) |
| `hmac` | HMAC secrets (HS256/HS384/HS512) |
| `all` | All key types |

## Example

```toml
[dev-dependencies]
uselesskey-jsonwebtoken = { version = "0.2", features = ["rsa"] }
jsonwebtoken = { version = "10", features = ["use_pem", "rust_crypto"] }
```

```rust
use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uselesskey_core::Factory;
use uselesskey_jsonwebtoken::JwtKeyExt;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: usize,
}

let fx = Factory::random();
let keypair = fx.rsa("issuer", RsaSpec::rs256());

let claims = Claims { sub: "user-1".into(), exp: 2_000_000_000 };
let token = encode(&Header::new(Algorithm::RS256), &claims, &keypair.encoding_key()).unwrap();
let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &Validation::new(Algorithm::RS256)).unwrap();

assert_eq!(decoded.claims, claims);
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
