# uselesskey-ed25519

Ed25519 key fixtures for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Provides `Ed25519FactoryExt` to generate deterministic or random Ed25519 keypairs with cached generation.

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS output via `uselesskey-jwk` |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

let fx = Factory::random();
let ed = fx.ed25519("signer", Ed25519Spec::new());

let pem = ed.private_key_pem();   // PKCS#8 PEM
let der = ed.public_key_spki_der(); // SPKI DER
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
