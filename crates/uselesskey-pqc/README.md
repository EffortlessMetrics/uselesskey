# uselesskey-pqc

Experimental post-quantum-crypto fixture shapes for tests.

## Scope

`uselesskey-pqc` is intentionally focused on **shape-first** test fixtures:
- large public keys
- large signatures
- large ciphertext/KEM artifacts
- malformed size/truncation negative fixtures

This crate currently defaults to opaque vectors to support parser, buffer, and TLS-prep test scenarios.

## Stability and production-readiness

This crate is experimental and does **not** claim production-ready PQC support.
`FixtureMode::Real` is reserved for future backend integrations once Rust ecosystem support is mature and stable.

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_pqc::{FixtureMode, PqcFactoryExt, PqcSpec};

let fx = Factory::deterministic_from_str("pqc-tests");
let spec = PqcSpec::ml_kem_level3(FixtureMode::Opaque);

let fixture = fx.pqc("tls-client-kem", spec);
assert!(fixture.public_bytes.len() > 1000);
assert!(fixture.ciphertext.is_some());
```
