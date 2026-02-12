# uselesskey-jsonwebtoken

[`jsonwebtoken`](https://docs.rs/jsonwebtoken) integration for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Returns `jsonwebtoken::EncodingKey` and `DecodingKey` directly from uselesskey keypairs.

## Features

| Feature | Description |
|---------|-------------|
| `rsa` | RSA keypairs (RS256, RS384, RS512) |
| `ecdsa` | ECDSA keypairs (ES256, ES384) |
| `ed25519` | Ed25519 keypairs (EdDSA) |
| `hmac` | HMAC secrets (HS256, HS384, HS512) |
| `all` | All of the above |

## Example

```toml
[dev-dependencies]
uselesskey-jsonwebtoken = { version = "0.2", features = ["all"] }
jsonwebtoken = { version = "10", features = ["use_pem", "rust_crypto"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_jsonwebtoken::JwtKeyExt;
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation};

let fx = Factory::random();
let keypair = fx.rsa("my-issuer", RsaSpec::rs256());

let token = encode(&Header::new(Algorithm::RS256), &claims, &keypair.encoding_key()).unwrap();
let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &Validation::new(Algorithm::RS256)).unwrap();
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
