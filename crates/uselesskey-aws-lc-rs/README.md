# uselesskey-aws-lc-rs

`aws-lc-rs` adapter traits for `uselesskey` fixtures.

Converts fixture keypairs into `aws-lc-rs` signing key types for tests that integrate directly with aws-lc-rs APIs.

## Features

| Feature | Description |
|---------|-------------|
| `native` | Enable the `aws-lc-rs` dependency (requires NASM on Windows) |
| `rsa` | RSA -> `aws_lc_rs::rsa::KeyPair` |
| `ecdsa` | ECDSA -> `aws_lc_rs::signature::EcdsaKeyPair` |
| `ed25519` | Ed25519 -> `aws_lc_rs::signature::Ed25519KeyPair` |
| `all` | `native` plus all key adapters |

When `native` is disabled, this crate builds as a no-op and exports no adapter traits.

## Example

```toml
[dev-dependencies]
uselesskey-aws-lc-rs = { version = "0.5.1", features = ["native", "rsa"] }
```

```rust
use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let keypair = rsa.rsa_key_pair_aws_lc_rs();

assert!(keypair.public_modulus_len() > 0);
```

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.

