# uselesskey-rustcrypto

[RustCrypto](https://github.com/RustCrypto) integration for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Converts uselesskey keypairs into native RustCrypto types (`rsa::RsaPrivateKey`, `p256::ecdsa::SigningKey`, `ed25519_dalek::SigningKey`, `hmac::Hmac`).

## Features

| Feature | Description |
|---------|-------------|
| `rsa` | RSA -> `rsa::RsaPrivateKey` / `RsaPublicKey` |
| `ecdsa` | ECDSA -> `p256::ecdsa::SigningKey` / `p384::ecdsa::SigningKey` |
| `ed25519` | Ed25519 -> `ed25519_dalek::SigningKey` / `VerifyingKey` |
| `hmac` | HMAC -> `hmac::Hmac<Sha256>` / `Sha384` / `Sha512` |
| `all` | All of the above |

## Example

```toml
[dev-dependencies]
uselesskey-rustcrypto = { version = "0.1", features = ["all"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_rustcrypto::RustCryptoRsaExt;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{Signer, Verifier};
use sha2::Sha256;

let fx = Factory::random();
let keypair = fx.rsa("test", RsaSpec::rs256());

let private_key = keypair.rsa_private_key();
let signing_key = SigningKey::<Sha256>::new(private_key);
let signature = signing_key.sign(b"hello world");
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
