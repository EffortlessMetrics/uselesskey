# uselesskey-feature-grid

Canonical feature flag and matrix definitions for `uselesskey` test automation.

This crate intentionally contains only compile-time constants to keep
`xtask` and BDD automation aligned.

## Exports

- `FeatureSet` — a matrix entry of a name and Cargo CLI args.
- `CORE_FEATURE_MATRIX` — standard workspace feature-check matrix.
- `BDD_FEATURE_MATRIX` — BDD feature matrix for `uselesskey-bdd`.
- `UK_FEATURE_*` constants for all `uselesskey-bdd` feature flags.
- `UK_FEATURE_SETS` — canonical list of all `uselesskey-bdd` feature strings.
- `BDD_FEATURE_SETS` — all feature sets in the BDD matrix.
