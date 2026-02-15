# uselesskey-rsa

RSA key fixtures (PKCS#8/SPKI in PEM/DER) for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Provides `RsaFactoryExt` to generate deterministic or random RSA keypairs with cached generation.

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS output via `uselesskey-jwk` |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());

let pem = rsa.private_key_pem();   // PKCS#8 PEM
let der = rsa.public_key_spki_der(); // SPKI DER
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
