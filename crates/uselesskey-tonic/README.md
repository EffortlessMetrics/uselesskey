# uselesskey-tonic

`tonic` transport TLS adapters for `uselesskey` X.509 fixtures.

Converts fixture certs and chains into `tonic::transport` TLS types:

- `Identity`
- `Certificate`
- `ServerTlsConfig`
- `ClientTlsConfig`

## Features

| Feature | Description |
|---------|-------------|
| `x509` (default) | Enable X.509 cert/chain adapter traits |

## Example

```toml
[dev-dependencies]
uselesskey-tonic = "0.3"
uselesskey-core = "0.3"
uselesskey-x509 = "0.3"
```

```rust
use uselesskey_core::Factory;
use uselesskey_tonic::{TonicClientTlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

let fx = Factory::random();
let chain = fx.x509_chain("grpc-service", ChainSpec::new("test.example.com"));

let server_tls = chain.server_tls_config_tonic();
let client_tls = chain.client_tls_config_tonic("test.example.com");

let _ = (server_tls, client_tls);
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
