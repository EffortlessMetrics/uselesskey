# uselesskey-ring

[`ring`](https://docs.rs/ring) 0.17 integration for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Converts uselesskey keypairs into ring native signing key types for direct use in code that depends on ring.

## Features

| Feature | Description |
|---------|-------------|
| `rsa` | RSA keypairs -> `ring::rsa::KeyPair` |
| `ecdsa` | ECDSA keypairs -> `ring::signature::EcdsaKeyPair` |
| `ed25519` | Ed25519 keypairs -> `ring::signature::Ed25519KeyPair` |
| `all` | All of the above |

## Example

```toml
[dev-dependencies]
uselesskey-ring = { version = "0.1", features = ["all"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_ring::RingRsaKeyPairExt;

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let ring_kp = rsa.rsa_key_pair_ring();  // ring::rsa::KeyPair
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
