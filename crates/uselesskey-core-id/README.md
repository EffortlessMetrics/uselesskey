# uselesskey-core-id

Core identity primitives shared by microcrate-facing and top-level `uselesskey` APIs.

## Purpose

- Model derivation identities (`ArtifactId`) used for cache keying.
- Derive per-artifact seeds from `(master seed, artifact id)`.
- Re-export [`Seed`] from `uselesskey-core-seed` for convenience.

This crate is intentionally small so it can be composed by multiple producers while
keeping determinism behavior stable across crate boundaries.
