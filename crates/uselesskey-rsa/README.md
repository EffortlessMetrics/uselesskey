# uselesskey-rsa

[![Crates.io](https://img.shields.io/crates/v/uselesskey-rsa.svg)](https://crates.io/crates/uselesskey-rsa)
[![docs.rs](https://docs.rs/uselesskey-rsa/badge.svg)](https://docs.rs/uselesskey-rsa)

RSA key fixtures for testing — generates PKCS#8 private keys and SPKI public
keys (PEM/DER), with negative variants for parser and validator tests.

Part of the [`uselesskey`](https://crates.io/crates/uselesskey) workspace. Use
the facade crate for the simplest experience, or depend on this crate directly
for minimal compile time.

## Usage

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());

// Private key
let private_pem = rsa.private_key_pkcs8_pem();
let private_der = rsa.private_key_pkcs8_der();

// Public key
let public_pem = rsa.public_key_spki_pem();
let public_der = rsa.public_key_spki_der();

assert!(private_pem.contains("BEGIN PRIVATE KEY"));
```

### Specs

| Constructor | Key size |
|-------------|----------|
| `RsaSpec::rs256()` | 2048-bit (default) |
| `RsaSpec::new(3072)` | 3072-bit |
| `RsaSpec::new(4096)` | 4096-bit |

### Negative Fixtures

```rust
use uselesskey_core::Factory;
use uselesskey_core::negative::CorruptPem;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

let fx = Factory::random();
let rsa = fx.rsa("test", RsaSpec::rs256());

let bad_pem   = rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
let truncated = rsa.private_key_pkcs8_der_truncated(32);
let mismatch  = rsa.mismatched_public_key_spki_der();
```

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS output via `uselesskey-jwk` |

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
