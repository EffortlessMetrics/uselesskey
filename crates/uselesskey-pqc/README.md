# uselesskey-pqc (experimental)

Experimental post-quantum fixture generator for test suites that need:

- large key/signature/ciphertext payloads,
- deterministic regeneration from `seed + label + spec`,
- malformed size negatives (truncation and oversize).

This crate is **not** a production PQC implementation and is **not** re-exported by the stable `uselesskey` facade.

## Current scope

- Opaque fixture vectors first (default mode)
- API scaffolding for future real mode (`ML-KEM`, `ML-DSA`)
- Parser and buffer boundary testing helpers

## Example

```rust
use uselesskey_core::{Factory, Seed};
use uselesskey_pqc::{PqcFactoryExt, PqcSecurityLevel, PqcSpec};

let fx = Factory::deterministic(Seed::from_env_value("example-seed").unwrap());
let fixture = fx.pqc("tls-kem", PqcSpec::ml_kem(PqcSecurityLevel::Level3));

assert!(!fixture.public_bytes().is_empty());
assert!(!fixture.ciphertext().is_empty());
```
