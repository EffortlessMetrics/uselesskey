# uselesskey-core-sink

Published-internal compatibility shim.

Tempfile sink ownership moved into `uselesskey-core`. Existing imports from this
crate remain available during the compatibility-shim period:

```rust
use uselesskey_core_sink::TempArtifact;
```

Prefer `uselesskey-core` for supported extension work. The canonical raw sink
implementation now lives at `uselesskey_core::srp::sink`; the supported
error-converting wrapper remains available as `uselesskey_core::TempArtifact`.
