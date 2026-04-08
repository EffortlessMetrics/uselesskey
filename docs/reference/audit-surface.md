# Audit Surface

Regenerate this table with:

```bash
cargo xtask audit-surface
```

The latest generated receipt also lives at `target/xtask/audit-surface/latest.md`.

The committed table below intentionally omits machine-dependent dependency counts so docs stay stable across CI runners and developer machines.

## Current receipt

workspace cargo-deny advisories: `ok`

| lane | package | markers | class |
| --- | --- | --- | --- |
| entropy | uselesskey-entropy | none | common-lane-clean |
| token | uselesskey-token | none | common-lane-clean |
| rsa | uselesskey-rsa | rsa-legacy-0.9, rsa-modern-0.10 | specialized-lane |
| materialize-shape | materialize-shape-buildrs-example | none | common-lane-clean |
| materialize-rsa | materialize-buildrs-example | rsa-legacy-0.9, rsa-modern-0.10 | specialized-lane |
| jsonwebtoken-adapter | uselesskey-jsonwebtoken | jsonwebtoken, rsa-legacy-0.9, rsa-modern-0.10 | adapter-island |
| pgp-adapter | uselesskey-pgp | pgp, rsa-legacy-0.9 | adapter-island |
