# uselesskey-x509

X.509 certificate fixtures for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Generate self-signed certificates and 3-level certificate chains (Root CA, Intermediate CA, Leaf) with deterministic or random key material. Includes negative fixture variants for testing error handling (expired CA, wrong issuer, self-signed leaf, reversed chain, revoked leaf, and more).

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK output for underlying RSA keys |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_x509::{X509FactoryExt, X509Spec};

let fx = Factory::deterministic(b"test-seed");
let cert = fx.x509("server", X509Spec::self_signed());

let cert_pem = cert.cert_pem();
let key_pem = cert.key_pem();
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
