# uselesskey-core-hash

Published-internal compatibility shim.

Hashing implementation ownership moved into `uselesskey-core`. Existing imports
from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_hash::{hash32, write_len_prefixed};
```

Prefer `uselesskey-core` for supported extension work. The canonical hashing
implementation now lives at `uselesskey_core::srp::hash`.
