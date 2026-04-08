# Audit Surface

Regenerate this table with:

```bash
cargo xtask audit-surface
```

The latest generated receipt also lives at `target/xtask/audit-surface/latest.md`.

## Current receipt

workspace cargo-deny advisories: `ok`

| lane | package | dep count | markers | class |
| --- | --- | ---: | --- | --- |
| entropy | uselesskey-entropy | 58 | none | common-lane-clean |
| token | uselesskey-token | 87 | none | common-lane-clean |
| rsa | uselesskey-rsa | 127 | rsa-legacy-0.9, rsa-modern-0.10 | specialized-lane |
| materialize-shape | materialize-shape-buildrs-example | 81 | none | common-lane-clean |
| materialize-rsa | materialize-buildrs-example | 120 | rsa-legacy-0.9, rsa-modern-0.10 | specialized-lane |
| jsonwebtoken-adapter | uselesskey-jsonwebtoken | 144 | jsonwebtoken, rsa-legacy-0.9, rsa-modern-0.10 | adapter-island |
| pgp-adapter | uselesskey-pgp | 204 | pgp, rsa-legacy-0.9 | adapter-island |
