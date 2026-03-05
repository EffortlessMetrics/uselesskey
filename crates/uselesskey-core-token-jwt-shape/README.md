# uselesskey-core-token-jwt-shape

JWT-shaped OAuth access token fixture primitives for `uselesskey`.

## Purpose

- Generate deterministic OAuth access-token strings in `header.payload.signature` shape.
- Keep JWT-shape payload defaults and segment-size constants in one SRP crate.

This crate is consumed by `uselesskey-core-token-shape` and re-exported through
higher-level token fixture crates.
