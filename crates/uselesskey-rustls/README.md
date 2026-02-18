# uselesskey-rustls

`rustls-pki-types` and `rustls` config adapters for `uselesskey` fixtures.

Converts fixture certs and keys into `CertificateDer` / `PrivateKeyDer`, with optional server/client/mTLS config builders.

## Features

| Feature | Description |
|---------|-------------|
| `x509` (default) | X.509 cert and chain conversions |
| `rsa` | RSA keypairs -> `PrivateKeyDer` |
| `ecdsa` | ECDSA keypairs -> `PrivateKeyDer` |
| `ed25519` | Ed25519 keypairs -> `PrivateKeyDer` |
| `all` | All key conversion traits |
| `server-config` | `rustls::ServerConfig` builders |
| `client-config` | `rustls::ClientConfig` builders |
| `tls-config` | Both server and client config builders |
| `rustls-ring` | ring crypto provider integration |
| `rustls-aws-lc-rs` | aws-lc-rs crypto provider integration |

## Example

```toml
[dev-dependencies]
uselesskey-rustls = { version = "0.3", features = ["tls-config", "rustls-ring"] }
```

```rust
use uselesskey_core::Factory;
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

let fx = Factory::random();
let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));

let server = chain.server_config_rustls();
let client = chain.client_config_rustls();

let _ = (server, client);
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
