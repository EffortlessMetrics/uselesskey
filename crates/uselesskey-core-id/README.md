# uselesskey-core-id

Published-internal compatibility shim.

Identity and derivation implementation ownership moved into `uselesskey-core`.
Existing imports from this crate remain available during the compatibility-shim
period:

```rust
use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed};
```

Prefer `uselesskey-core` for supported extension work. The canonical identity
implementation now lives at `uselesskey_core::srp::identity`.
