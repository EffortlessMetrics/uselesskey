# uselesskey-core-keypair

Published-internal compatibility shim.

Shared PKCS#8/SPKI helper ownership moved into `uselesskey-core`. Existing
imports from this crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;
```

Prefer the fixture-family crates (`uselesskey-rsa`, `uselesskey-ecdsa`,
`uselesskey-ed25519`) or the `uselesskey` facade for normal usage. The
canonical helper implementation now lives at `uselesskey_core::srp::keypair`.
