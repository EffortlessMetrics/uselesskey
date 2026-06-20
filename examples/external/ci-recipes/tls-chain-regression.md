# TLS Chain Regression

Use this when a downstream TLS verifier or adapter test needs deterministic
certificate-chain fixtures.

## Rust Test Path

```toml
[dev-dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["x509"] }
uselesskey-rustls = { version = "0.9.1", features = ["tls-config", "rustls-ring"] }
```

```rust
use uselesskey::{ChainSpec, Factory, X509FactoryExt};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};

let fx = Factory::deterministic_from_str("downstream-tls");
let chain = fx.x509_chain("service", ChainSpec::new("valid.tls.uselesskey.test"));

let server = chain.server_config_rustls();
let client = chain.client_config_rustls();
```

Use the installed `tls` profile when a CI job needs file-based negative chain
fixtures and metadata-only bundle receipts.

## Installed Bundle Path

```bash
uselesskey bundle --profile tls --out target/uselesskey-tls
uselesskey verify-bundle target/uselesskey-tls
uselesskey inspect-bundle target/uselesskey-tls
uselesskey audit-bundle \
  target/uselesskey-tls \
  --ci \
  --expect-profile tls \
  --policy strict \
  --out target/uselesskey-tls-audit
```

## Boundary

This proves local fixture generation and bundle consistency. It does not prove
browser trust-store behavior, production PKI, revocation policy, mTLS behavior,
or downstream verifier correctness.
