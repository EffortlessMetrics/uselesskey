# uselesskey-core-negative-pem

Published-internal compatibility shim.

PEM negative helper ownership moved into `uselesskey-core`. Existing imports
from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};
```

Prefer `uselesskey-core` for supported extension work. The canonical PEM helper
implementation now lives at `uselesskey_core::srp::negative::pem`.
