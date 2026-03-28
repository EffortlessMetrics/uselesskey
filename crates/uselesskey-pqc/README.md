# uselesskey-pqc

Experimental PQC fixture helpers for parser, buffer, and TLS-prep testing.

> This crate is intentionally **experimental** and does **not** claim production-ready PQC support.

## What it provides today

- Deterministic, cacheable **opaque** fixtures for:
  - ML-KEM-shaped key/ciphertext sizes
  - ML-DSA-shaped key/signature sizes
- Negative fixtures for malformed size/truncation cases.

## What it does not provide (yet)

- Stable facade re-exports from `uselesskey`
- Interop guarantees with real PQC backend libraries
- Production cryptography claims

## Usage

```rust
use uselesskey_core::{Factory, Seed};
use uselesskey_pqc::{PqcAlgorithm, PqcFactoryExt, PqcFixtureMode, PqcSecurityLevel, PqcSpec};

let fx = Factory::deterministic(Seed::from_env_value("pqc-demo").unwrap());
let spec = PqcSpec::new(
    PqcAlgorithm::MlDsa,
    PqcSecurityLevel::L3,
    PqcFixtureMode::Opaque,
);

let fixture = fx.pqc("sig-parser", spec).unwrap();
assert_eq!(fixture.artifact_kind(), "signature");
assert!(fixture.public_bytes().len() > 1000);
```
