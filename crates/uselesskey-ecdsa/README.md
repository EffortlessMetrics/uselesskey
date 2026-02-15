# uselesskey-ecdsa

ECDSA P-256/P-384 key fixtures for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Provides `EcdsaFactoryExt` to generate deterministic or random ECDSA keypairs (ES256/ES384) with cached generation.

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS output via `uselesskey-jwk` |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

let fx = Factory::random();
let ecdsa = fx.ecdsa("signer", EcdsaSpec::es256());

let pem = ecdsa.private_key_pem();   // PKCS#8 PEM
let der = ecdsa.public_key_spki_der(); // SPKI DER
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
