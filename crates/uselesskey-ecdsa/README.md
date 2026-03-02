# uselesskey-ecdsa

[![Crates.io](https://img.shields.io/crates/v/uselesskey-ecdsa.svg)](https://crates.io/crates/uselesskey-ecdsa)
[![docs.rs](https://docs.rs/uselesskey-ecdsa/badge.svg)](https://docs.rs/uselesskey-ecdsa)

ECDSA P-256/P-384 key fixtures for testing — generates PKCS#8 private keys and
SPKI public keys (PEM/DER) for ES256 and ES384 workflows, with deterministic
derivation and cache-by-identity.

Part of the [`uselesskey`](https://crates.io/crates/uselesskey) workspace. Use
the facade crate for the simplest experience, or depend on this crate directly
for minimal compile time.

## Usage

```rust
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

let fx = Factory::random();
let keypair = fx.ecdsa("signer", EcdsaSpec::es256());

// Private key
let private_pem = keypair.private_key_pkcs8_pem();
let private_der = keypair.private_key_pkcs8_der();

// Public key
let public_pem = keypair.public_key_spki_pem();
let public_der = keypair.public_key_spki_der();

assert!(private_pem.contains("BEGIN PRIVATE KEY"));
```

### Specs

| Constructor | Curve |
|-------------|-------|
| `EcdsaSpec::es256()` | P-256 (secp256r1) |
| `EcdsaSpec::es384()` | P-384 (secp384r1) |

### Negative Fixtures

```rust
use uselesskey_core::Factory;
use uselesskey_core::negative::CorruptPem;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

let fx = Factory::random();
let keypair = fx.ecdsa("test", EcdsaSpec::es256());

let bad_pem   = keypair.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
let truncated = keypair.private_key_pkcs8_der_truncated(32);
let mismatch  = keypair.mismatched_public_key_spki_der();
```

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | JWK/JWKS output via `uselesskey-jwk` |

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
