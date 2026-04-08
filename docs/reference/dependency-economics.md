# Dependency Economics

Regenerate this table with:

```bash
cargo xtask economics
```

The latest generated receipt also lives at `target/xtask/economics/latest.md`.

The committed table below intentionally omits machine-dependent timing columns so docs stay stable across CI runners and developer machines.

## Current receipt

| use case | recommended lane | dep count | smoke |
| --- | --- | ---: | --- |
| entropy-only | uselesskey-entropy | 58 | ok |
| token-shape-only | uselesskey-token | 87 | ok |
| runtime-rsa | uselesskey-rsa | 127 | ok |
| build-time-shape-fixtures | uselesskey-cli materialize (shape-only) | 81 | ok |
| build-time-rsa-fixtures | uselesskey-cli materialize (rsa) | 120 | ok |
