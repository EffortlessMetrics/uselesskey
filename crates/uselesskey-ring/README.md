# uselesskey-ring

`ring` 0.17 adapter traits for `uselesskey` fixtures.

Converts fixture keypairs into native ring signing key types for tests that call ring APIs directly.

## Features

| Feature | Description |
|---------|-------------|
| `rsa` | RSA -> `ring::rsa::KeyPair` |
| `ecdsa` | ECDSA -> `ring::signature::EcdsaKeyPair` |
| `ed25519` | Ed25519 -> `ring::signature::Ed25519KeyPair` |
| `all` | All key adapters |

## Example

```toml
[dev-dependencies]
uselesskey-ring = { version = "0.5.0", features = ["rsa"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_ring::RingRsaKeyPairExt;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let keypair = rsa.rsa_key_pair_ring();

assert!(keypair.public().modulus_len() > 0);
```

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.

