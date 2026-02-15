# uselesskey-core

Core factory, derivation, and caching engine for [uselesskey](https://docs.rs/uselesskey) test fixtures.

This crate provides the `Factory` struct (random and deterministic modes), BLAKE3-based seed derivation, and a concurrent `DashMap` cache. Most users should depend on the [`uselesskey`](https://docs.rs/uselesskey) facade crate instead of using this directly.

## Example

```rust
use uselesskey_core::Factory;

// Random mode -- fresh key material every run
let fx = Factory::random();

// Deterministic mode -- reproducible from seed
let fx = Factory::deterministic(b"my-test-seed");
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
