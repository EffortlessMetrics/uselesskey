# uselesskey-core-negative

Published-internal compatibility shim.

Generic negative fixture helper ownership moved into `uselesskey-core`.
Existing imports from this crate remain available during the compatibility-shim
period:

```rust
use uselesskey_core_negative::{CorruptPem, corrupt_pem, truncate_der};
```

Prefer `uselesskey-core` for supported extension work, or the fixture-family
crates for normal negative fixture usage. The canonical generic helper
implementation now lives at `uselesskey_core::srp::negative`.
