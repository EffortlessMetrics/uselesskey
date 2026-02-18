# uselesskey-ecdsa

ECDSA P-256/P-384 key fixtures for `uselesskey` test suites.

Generates PKCS#8 private keys and SPKI public keys (PEM/DER) for ES256 and ES384 workflows, with deterministic derivation and cache-by-identity.

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS helpers via `uselesskey-jwk` |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

let fx = Factory::random();
let keypair = fx.ecdsa("signer", EcdsaSpec::es256());

let private_pem = keypair.private_key_pkcs8_pem();
let public_der = keypair.public_key_spki_der();

assert!(private_pem.contains("BEGIN PRIVATE KEY"));
assert!(!public_der.is_empty());
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
