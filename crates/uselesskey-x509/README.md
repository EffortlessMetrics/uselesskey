# uselesskey-x509

[![Crates.io](https://img.shields.io/crates/v/uselesskey-x509.svg)](https://crates.io/crates/uselesskey-x509)
[![docs.rs](https://docs.rs/uselesskey-x509/badge.svg)](https://docs.rs/uselesskey-x509)

X.509 certificate fixtures for testing — generates self-signed certificates and
3-level chains (root CA → intermediate CA → leaf), with deterministic derivation
and negative fixture variants for TLS error-handling tests.

Part of the [`uselesskey`](https://crates.io/crates/uselesskey) workspace. Use
the facade crate for the simplest experience, or depend on this crate directly
for minimal compile time.

## Usage

### Self-Signed Certificate

```rust
use uselesskey_core::Factory;
use uselesskey_x509::{X509FactoryExt, X509Spec};

let fx = Factory::random();
let cert = fx.x509_self_signed("server", X509Spec::self_signed("test.example.com"));

let cert_pem = cert.cert_pem();
let key_pem  = cert.private_key_pkcs8_pem();

assert!(cert_pem.contains("BEGIN CERTIFICATE"));
assert!(key_pem.contains("BEGIN PRIVATE KEY"));
```

### Certificate Chain (Root → Intermediate → Leaf)

```rust
use uselesskey_core::Factory;
use uselesskey_x509::{X509FactoryExt, ChainSpec};

let fx = Factory::random();
let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

// Standard TLS server chain (leaf + intermediate, no root)
let chain_pem = chain.chain_pem();

// Individual components
let root_pem = chain.root_cert_pem();
let leaf_key = chain.leaf_private_key_pkcs8_pem();
```

### Negative Fixtures

Generate intentionally invalid certificates for testing error-handling paths:

```rust
use uselesskey_core::Factory;
use uselesskey_x509::{X509FactoryExt, ChainSpec};

let fx = Factory::random();
let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));

// Expired leaf certificate
let expired = chain.expired_leaf();

// Hostname mismatch (SAN doesn't match expected hostname)
let wrong_host = chain.hostname_mismatch("wrong.example.com");

// Signed by an unknown CA (not in your trust store)
let unknown = chain.unknown_ca();

// Revoked leaf with CRL signed by the intermediate CA
let revoked = chain.revoked_leaf();
let crl_pem = revoked.crl_pem().expect("CRL present for revoked variant");
```

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | Pass-through for `uselesskey-rsa/jwk` compatibility |

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
