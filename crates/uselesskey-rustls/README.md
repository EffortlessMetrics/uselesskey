# uselesskey-rustls

[`rustls-pki-types`](https://docs.rs/rustls-pki-types) integration for [uselesskey](https://docs.rs/uselesskey) test fixtures.

Converts uselesskey X.509 certificates and keypairs into rustls types, with optional `ServerConfig` / `ClientConfig` builders for TLS and mTLS.

## Features

| Feature | Description |
|---------|-------------|
| `x509` (default) | X.509 certificates and chains |
| `rsa` | RSA keypairs -> `PrivateKeyDer` |
| `ecdsa` | ECDSA keypairs -> `PrivateKeyDer` |
| `ed25519` | Ed25519 keypairs -> `PrivateKeyDer` |
| `all` | All key types |
| `server-config` | `rustls::ServerConfig` builders (implies `x509`) |
| `client-config` | `rustls::ClientConfig` builders (implies `x509`) |
| `tls-config` | Both server and client config builders |
| `rustls-ring` | Use ring as the rustls crypto provider |
| `rustls-aws-lc-rs` | Use aws-lc-rs as the rustls crypto provider |

## Example

```toml
[dev-dependencies]
uselesskey-rustls = { version = "0.1", features = ["tls-config", "rustls-ring"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_x509::{X509FactoryExt, ChainSpec};
use uselesskey_rustls::{RustlsServerConfigExt, RustlsClientConfigExt};

let fx = Factory::random();
let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

let server_config = chain.server_config_rustls();
let client_config = chain.client_config_rustls();
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
