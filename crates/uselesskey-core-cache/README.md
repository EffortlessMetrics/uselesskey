# uselesskey-core-cache

Published-internal compatibility shim.

Cache implementation ownership moved into `uselesskey-core`. Existing imports
from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_cache::ArtifactCache;
```

Prefer `uselesskey-core` for supported extension work. The canonical cache
implementation now lives at `uselesskey_core::srp::cache`.

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Uses `DashMap` for concurrent cache access |
| `default-features = false` | Uses `spin::Mutex<BTreeMap<...>>` for `no_std` builds |

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
