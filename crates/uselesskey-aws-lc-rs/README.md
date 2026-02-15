# uselesskey-aws-lc-rs

[`aws-lc-rs`](https://docs.rs/aws-lc-rs) integration for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Converts uselesskey keypairs into aws-lc-rs native signing key types. Includes a `native` feature flag for wasm-safe builds.

## Features

| Feature | Description |
|---------|-------------|
| `native` | Enable `aws-lc-rs` dependency (requires NASM on Windows) |
| `rsa` | RSA keypairs -> `aws_lc_rs::rsa::KeyPair` |
| `ecdsa` | ECDSA keypairs -> `aws_lc_rs::signature::EcdsaKeyPair` |
| `ed25519` | Ed25519 keypairs -> `aws_lc_rs::signature::Ed25519KeyPair` |
| `all` | All key types |

When the `native` feature is disabled, this crate compiles as a no-op with no traits or implementations available. This is useful for wasm targets where `aws-lc-rs` cannot build.

## Example

```toml
[dev-dependencies]
uselesskey-aws-lc-rs = { version = "0.2", features = ["native", "all"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;

let fx = Factory::random();
let rsa = fx.rsa("signer", RsaSpec::rs256());
let kp = rsa.rsa_key_pair_aws_lc_rs();  // aws_lc_rs::rsa::KeyPair
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
