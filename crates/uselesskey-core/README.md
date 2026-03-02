# uselesskey-core

[![Crates.io](https://img.shields.io/crates/v/uselesskey-core.svg)](https://crates.io/crates/uselesskey-core)
[![docs.rs](https://docs.rs/uselesskey-core/badge.svg)](https://docs.rs/uselesskey-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Core factory, deterministic derivation, and cache primitives for
[`uselesskey`](https://crates.io/crates/uselesskey) test fixtures.

Most test suites should depend on the **facade crate**
([`uselesskey`](https://crates.io/crates/uselesskey)). Use `uselesskey-core`
directly when building extension crates or when you need only the core
primitives.

## What It Provides

- `Factory` in random and deterministic modes
- Order-independent derivation from `(domain, label, spec, variant)`
- Per-process cache for generated artifacts (powered by `uselesskey-core-cache`)
- Generic negative helpers for corrupted PEM / truncated DER
- Tempfile sinks when `std` is enabled (implemented in `uselesskey-core-sink`)

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Random mode, env seed helpers, tempfile sink, concurrent cache |
| `default-features = false` | `no_std` deterministic derivation and negative helpers |

## Example

```rust
use uselesskey_core::{Factory, Mode, Seed};

// Deterministic mode: same seed always produces the same artifacts
let seed = Seed::from_env_value("ci-seed").unwrap();
let fx = Factory::deterministic(seed);

assert!(matches!(fx.mode(), Mode::Deterministic { .. }));

// Random mode: different keys each run (still cached per-process)
let fx = Factory::random();
```

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
