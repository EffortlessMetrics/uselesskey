# uselesskey-ed25519

Ed25519 key fixtures for `uselesskey` test suites.

Generates PKCS#8 private keys and SPKI public keys (PEM/DER) with deterministic derivation, random mode, and negative-fixture helpers.

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS helpers via `uselesskey-jwk` |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

let fx = Factory::random();
let keypair = fx.ed25519("signer", Ed25519Spec::new());

let private_pem = keypair.private_key_pkcs8_pem();
let public_der = keypair.public_key_spki_der();

assert!(private_pem.contains("BEGIN PRIVATE KEY"));
assert!(!public_der.is_empty());
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
