# Dependency Economics

Regenerate this table with:

```bash
cargo xtask economics
```

The latest generated receipt also lives at `target/xtask/economics/latest.md`.

The committed table below intentionally omits machine-dependent timing columns so docs stay stable across CI runners and developer machines.

## Current receipt

| use case | recommended lane | smoke |
| --- | --- | --- |
| entropy-only | uselesskey-entropy | ok |
| token-shape-only | uselesskey-token | ok |
| runtime-rsa | uselesskey-rsa | ok |
| build-time-shape-fixtures | uselesskey-cli materialize (shape-only) | ok |
| build-time-rsa-fixtures | uselesskey-cli materialize (rsa) | ok |
