# uselesskey-core-token

Deprecated compatibility shim.

Token-shape implementation ownership moved into `uselesskey-token`. Existing
imports from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_token::generate_token;
```

Prefer `uselesskey-token` or the `uselesskey` facade for supported token
fixture APIs.
