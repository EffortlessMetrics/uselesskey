# uselesskey-rsa

RSA key fixtures for `uselesskey` test suites.

Generates PKCS#8 private keys and SPKI public keys (PEM/DER), plus negative variants for parser and validator tests.

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS helpers via `uselesskey-jwk` |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());

let private_pem = rsa.private_key_pkcs8_pem();
let public_der = rsa.public_key_spki_der();

assert!(private_pem.contains("BEGIN PRIVATE KEY"));
assert!(!public_der.is_empty());
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
