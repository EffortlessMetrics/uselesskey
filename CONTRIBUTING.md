# Contributing

## Setup

- Install Rust stable.
- Optional tools:
  - `cargo install cargo-mutants`
  - `cargo install cargo-fuzz`
  - `cargo install cargo-nextest`
  - `cargo install cargo-deny`

## Common commands

```bash
cargo xtask ci
cargo xtask bdd
cargo xtask fuzz
cargo xtask mutants
```

## Design constraints

- Keep deterministic derivation stable (bump derivation version if you must change it).
- Debug output must not print key material.
- Prefer small, composable crates over “one giant crate”.
