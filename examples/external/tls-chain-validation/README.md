# TLS Chain Validation Fixtures

Use this downstream-shaped example when a TLS verifier or adapter test needs
deterministic certificate-chain fixtures and rustls config construction.

User job:

```text
I need deterministic TLS chain fixtures in Rust tests.
```

Dependencies:

```toml
[dev-dependencies]
uselesskey = { version = "0.10.0", default-features = false, features = ["x509"] }
uselesskey-rustls = { version = "0.10.0", features = ["tls-config", "rustls-ring"] }
```

First imports:

```rust
use uselesskey::{ChainSpec, Factory, X509FactoryExt};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
```

Positive path:

```text
Factory::deterministic_from_str("external-tls-chain-validation")
  -> fx.x509_chain("service", ChainSpec::new("valid.tls.uselesskey.test"))
  -> PEM chain plus rustls server/client config construction
```

Negative path:

```text
Use the CLI `tls` bundle profile when the test needs file-based expired,
hostname-mismatch, unknown-CA, or revoked-leaf fixtures.
```

```bash
cargo test
```

Installed CLI bundle audit path:

```bash
uselesskey bundle --profile tls --out target/uselesskey-tls
uselesskey audit-bundle --path target/uselesskey-tls --out target/uselesskey-tls-audit
```

This proves fixture and adapter construction for test code. It does not prove
production PKI, revocation, certificate transparency, mTLS, browser trust-store
behavior, production CA custody, or downstream verifier correctness.
