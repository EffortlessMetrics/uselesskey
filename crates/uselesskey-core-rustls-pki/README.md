Deprecated compatibility shim.

The canonical rustls-pki conversion traits now live in `uselesskey-rustls`:

```rust
use uselesskey_rustls::{RustlsPrivateKeyExt, RustlsCertExt, RustlsChainExt};
```

Prefer `uselesskey-rustls` (or the `uselesskey` facade) for supported PKI
fixture-conversion APIs. This crate is retained only to keep v0.7.x consumers
compiling and is scheduled for removal in a later v0.8.x PR.
