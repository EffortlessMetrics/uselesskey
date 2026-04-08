# uselesskey-jsonwebtoken

[![Crates.io](https://img.shields.io/crates/v/uselesskey-jsonwebtoken.svg)](https://crates.io/crates/uselesskey-jsonwebtoken)
[![docs.rs](https://docs.rs/uselesskey-jsonwebtoken/badge.svg)](https://docs.rs/uselesskey-jsonwebtoken)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

[`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) adapter for
[`uselesskey`](https://crates.io/crates/uselesskey) test fixtures.

Implements `JwtKeyExt` so fixture types return `jsonwebtoken::EncodingKey` and
`jsonwebtoken::DecodingKey` directly — no manual PEM parsing needed in tests.

## Features

| Feature | Description |
|---------|-------------|
| `rsa` | RSA keypairs (RS256/RS384/RS512) |
| `ecdsa` | ECDSA keypairs (ES256/ES384) |
| `ed25519` | Ed25519 keypairs (EdDSA) |
| `hmac` | HMAC secrets (HS256/HS384/HS512) |
| `all` | All key types |

## Usage

```toml
[dev-dependencies]
uselesskey-jsonwebtoken = { version = "0.6.0", features = ["rsa"] }
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

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.

