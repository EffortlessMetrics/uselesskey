# uselesskey-ed25519

[![Crates.io](https://img.shields.io/crates/v/uselesskey-ed25519.svg)](https://crates.io/crates/uselesskey-ed25519)
[![docs.rs](https://docs.rs/uselesskey-ed25519/badge.svg)](https://docs.rs/uselesskey-ed25519)

Ed25519 key fixtures for testing — generates PKCS#8 private keys and SPKI public
keys (PEM/DER) with deterministic derivation, random mode, and negative-fixture
helpers.

Part of the [`uselesskey`](https://crates.io/crates/uselesskey) workspace. Use
the facade crate for the simplest experience, or depend on this crate directly
for minimal compile time.

## Usage

```rust
use uselesskey_core::Factory;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

let fx = Factory::random();
let keypair = fx.ed25519("signer", Ed25519Spec::new());

// Private key
let private_pem = keypair.private_key_pkcs8_pem();
let private_der = keypair.private_key_pkcs8_der();

// Public key
let public_pem = keypair.public_key_spki_pem();
let public_der = keypair.public_key_spki_der();

assert!(private_pem.contains("BEGIN PRIVATE KEY"));
```

### Negative Fixtures

```rust
use uselesskey_core::Factory;
use uselesskey_core::negative::CorruptPem;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

let fx = Factory::random();
let keypair = fx.ed25519("test", Ed25519Spec::new());

let bad_pem   = keypair.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
let truncated = keypair.private_key_pkcs8_der_truncated(32);
let mismatch  = keypair.mismatched_public_key_spki_der();
```

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS output via `uselesskey-jwk` (OKP key type, EdDSA algorithm) |

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
