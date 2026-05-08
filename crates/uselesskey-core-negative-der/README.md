# uselesskey-core-negative-der

Published-internal compatibility shim.

DER negative helper ownership moved into `uselesskey-core`. Existing imports
from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_negative_der::{corrupt_der_deterministic, truncate_der};
```

Prefer `uselesskey-core` for supported extension work. The canonical DER helper
implementation now lives at `uselesskey_core::srp::negative::der`.
