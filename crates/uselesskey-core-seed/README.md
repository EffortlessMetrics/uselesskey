# uselesskey-core-seed

Published-internal compatibility shim.

Seed implementation ownership moved into `uselesskey-core`. Existing imports
from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_seed::Seed;
```

Prefer `uselesskey-core` for supported extension work, or the `uselesskey`
facade for normal fixture usage. The canonical seed implementation now lives at
`uselesskey_core::srp::seed`.
