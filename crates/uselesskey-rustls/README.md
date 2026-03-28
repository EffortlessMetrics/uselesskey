# uselesskey-rustls

[![Crates.io](https://img.shields.io/crates/v/uselesskey-rustls.svg)](https://crates.io/crates/uselesskey-rustls)
[![docs.rs](https://docs.rs/uselesskey-rustls/badge.svg)](https://docs.rs/uselesskey-rustls)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

[`rustls`](https://crates.io/crates/rustls) /
[`rustls-pki-types`](https://crates.io/crates/rustls-pki-types) adapter for
[`uselesskey`](https://crates.io/crates/uselesskey) test fixtures.

Converts fixture certs and keys into `CertificateDer` / `PrivateKeyDer`, with
optional `ServerConfig` / `ClientConfig` builders (including mTLS support).

## Features

| Feature | Description |
|---------|-------------|
| `x509` (default) | X.509 cert and chain conversions |
| `rsa` | RSA keypairs → `PrivateKeyDer` |
| `ecdsa` | ECDSA keypairs → `PrivateKeyDer` |
| `ed25519` | Ed25519 keypairs → `PrivateKeyDer` |
| `all` | All key conversion traits |
| `server-config` | `rustls::ServerConfig` builders |
| `client-config` | `rustls::ClientConfig` builders |
| `tls-config` | Both server and client config builders |
| `rustls-ring` | ring crypto provider integration |
| `rustls-aws-lc-rs` | aws-lc-rs crypto provider integration |

## Usage

```toml
<!-- docs-sync:usage-dependency-snippet-start -->
[dev-dependencies]
uselesskey-rustls = { version = "0.5.1", features = ["tls-config", "rustls-ring"] }
<!-- docs-sync:usage-dependency-snippet-end -->
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

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
