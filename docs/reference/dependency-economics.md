# Dependency Economics

Regenerate this table with:

```bash
cargo xtask economics
```

The latest generated receipt also lives at `target/xtask/economics/latest.md`.

## Current receipt

| use case | recommended lane | dep count | first check | repeat check | smoke |
| --- | --- | ---: | ---: | ---: | --- |
| entropy-only | uselesskey-entropy | 58 | 1.43s | 3.78s | ok |
| token-shape-only | uselesskey-token | 87 | 1.27s | 0.40s | ok |
| runtime-rsa | uselesskey-rsa | 127 | 2.69s | 0.79s | ok |
| build-time-shape-fixtures | uselesskey-cli materialize (shape-only) | 81 | 11.50s | 3.85s | ok |
| build-time-rsa-fixtures | uselesskey-cli materialize (rsa) | 120 | 13.29s | 1.45s | ok |
