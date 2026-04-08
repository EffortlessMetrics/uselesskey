# uselesskey-entropy

Deterministic high-entropy byte fixtures built on `uselesskey-core`.

Use this crate when tests need stable byte buffers without pulling in RSA,
X.509, PGP, or token-shape helpers.

```rust
use uselesskey_core::Factory;
use uselesskey_entropy::EntropyFactoryExt;

let fx = Factory::deterministic_from_str("entropy-fixtures");
let bytes = fx.entropy("scan-fixture").bytes(64);

assert_eq!(bytes.len(), 64);
```
