# uselesskey-core-factory

Published-internal compatibility shim.

Factory implementation ownership moved into `uselesskey-core`. Existing imports
from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_factory::{Factory, Mode};
```

Prefer `uselesskey-core` for supported extension work, or the `uselesskey`
facade for normal fixture usage. The canonical factory implementation now lives
at `uselesskey_core::srp::factory`.
