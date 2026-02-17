# uselesskey-core

Core factory, deterministic derivation, and cache primitives for `uselesskey` test fixtures.

Most test suites should depend on the facade crate (`uselesskey`). Use `uselesskey-core` directly when building extension crates.

## What It Provides

- `Factory` in random and deterministic modes
- Order-independent derivation from `(domain, label, spec, variant)`
- Per-process cache for generated artifacts
- Generic negative helpers for corrupted PEM / truncated DER
- Tempfile sinks when `std` is enabled

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Random mode, env seed helpers, tempfile sink, concurrent cache |
| `default-features = false` | `no_std` deterministic derivation and negative helpers |

## Example

```rust
use uselesskey_core::{Factory, Mode, Seed};

let seed = Seed::from_env_value("ci-seed").unwrap();
let fx = Factory::deterministic(seed);

assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
