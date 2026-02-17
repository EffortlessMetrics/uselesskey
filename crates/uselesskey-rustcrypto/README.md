# uselesskey-rustcrypto

RustCrypto adapter traits for `uselesskey` fixtures.

Converts fixture key material into native RustCrypto types (`rsa`, `p256`/`p384`, `ed25519-dalek`, `hmac`).

## Features

| Feature | Description |
|---------|-------------|
| `rsa` | `rsa::RsaPrivateKey` / `rsa::RsaPublicKey` adapters |
| `ecdsa` | P-256 and P-384 signing/verifying key adapters |
| `ed25519` | `ed25519_dalek::SigningKey` / `VerifyingKey` adapters |
| `hmac` | `hmac::Hmac<Sha256/Sha384/Sha512>` adapters |
| `all` | All adapters |

## Example

```toml
[dev-dependencies]
uselesskey-rustcrypto = { version = "0.2", features = ["rsa"] }
```

```rust
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Signer, Verifier};
use sha2::Sha256;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_rustcrypto::RustCryptoRsaExt;

let fx = Factory::random();
let keypair = fx.rsa("signer", RsaSpec::rs256());

let signing_key = SigningKey::<Sha256>::new_unprefixed(keypair.rsa_private_key());
let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(keypair.rsa_public_key());

let signature = signing_key.sign(b"hello");
verifying_key.verify(b"hello", &signature).unwrap();
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
