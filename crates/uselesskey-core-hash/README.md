# uselesskey-core-hash

Deterministic hashing primitives shared by fixture derivation codepaths.

## Purpose

- Compute BLAKE3 digests for deterministic seed/fixture derivation helpers.
- Write length-prefixed byte slices for unambiguous tuple hashing.
- Keep the implementation isolated so derived-seed behavior is reusable across microcrates.
