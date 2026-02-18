# uselesskey-x509

X.509 certificate fixtures for `uselesskey` test suites.

Generates self-signed certificates and 3-level chains (root CA -> intermediate CA -> leaf), with deterministic derivation and negative fixture variants.

## What It Provides

- `x509_self_signed(label, X509Spec)` for single certificates
- `x509_chain(label, ChainSpec)` for root/intermediate/leaf chains
- PEM and DER outputs for certs and private keys
- Negative fixtures: expired, hostname mismatch, unknown CA, revoked leaf (CRL)

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | Pass-through for `uselesskey-rsa/jwk` compatibility (no direct X.509 JWK API) |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_x509::{X509FactoryExt, X509Spec};

let fx = Factory::deterministic_from_env("USELESSKEY_SEED").unwrap_or_else(|_| Factory::random());
let cert = fx.x509_self_signed("server", X509Spec::self_signed("test.example.com"));

let cert_pem = cert.cert_pem();
let key_pem = cert.private_key_pkcs8_pem();

assert!(cert_pem.contains("BEGIN CERTIFICATE"));
assert!(key_pem.contains("BEGIN PRIVATE KEY"));
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
