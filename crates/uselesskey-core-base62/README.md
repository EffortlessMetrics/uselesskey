# uselesskey-core-base62

Deprecated compatibility shim.

Base62 implementation ownership moved into `uselesskey-token`. Existing imports
from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_base62::random_base62;
```

Prefer `uselesskey-token` or the `uselesskey` facade for supported token
fixture APIs.
