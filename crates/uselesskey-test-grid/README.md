# uselesskey-test-grid

This crate is the compatibility façade for `uselesskey-feature-grid`.

The canonical feature matrices used by `xtask` and automation are:

- standard feature-matrix checks
- BDD feature-matrix checks

This crate re-exports the canonical matrices and feature constants and is kept
for backwards compatibility.

## What it exports

- `FeatureSet` — tuple of a human-readable name and Cargo args.
- `CORE_FEATURE_MATRIX` — matrix for core workspace checks (`cargo check`).
- `BDD_FEATURE_MATRIX` — matrix for `uselesskey-bdd` matrix runs (`--features` sets).
- `uk-*` constants in `uselesskey-test-grid` define the BDD feature-flags exposed by `uselesskey-bdd`.

## Extensibility

Add a new BDD entry by appending a `FeatureSet` value to `BDD_FEATURE_MATRIX`.
Receipts, logging, and orchestration consume these identifiers directly, so
test names remain consistent without extra wiring.

### BDD feature flag conventions

Adapter-backed BDD coverage is now represented in the matrix with explicit
`all-features+<adapter>` entries (for example `all-features+rustls`).
That keeps adapter expansion explicit while retaining deterministic default behavior.
