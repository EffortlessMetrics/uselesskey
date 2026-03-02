# uselesskey-core-cache

Identity-keyed typed cache primitives shared by `uselesskey` fixture factories.

## Purpose

- Provide a process-local cache keyed by `ArtifactId`.
- Store generated fixtures as `Arc<dyn Any + Send + Sync>`.
- Preserve typed retrieval guarantees with explicit panic on type mismatch.
- Keep `std`/`no_std` behavior aligned with `uselesskey-core`.

This microcrate is intentionally focused on cache mechanics, not derivation or key generation.

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
