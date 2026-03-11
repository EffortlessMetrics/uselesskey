# uselesskey-core-token-shape

Low-level token shape primitives for `uselesskey`.

## Purpose

- Generate deterministic and realistic API key shapes.
- Generate opaque bearer token shapes.
- Delegate OAuth-like JWT-access-token shapes to `uselesskey-core-jwt-shape`.

This crate intentionally contains only token-shape construction and is used by
`uselesskey-core-token` and higher-level token fixture crates.
