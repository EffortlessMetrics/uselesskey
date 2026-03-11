# uselesskey-core-token-shape

Low-level token shape primitives for `uselesskey`.

## Purpose

- Generate deterministic and realistic API key shapes.
- Generate opaque bearer token shapes.
- Delegate OAuth-like JWT-access-token shape generation to
  `uselesskey-core-token-oauth-shape`.

This crate intentionally focuses on non-OAuth token-shape construction and is
used by `uselesskey-core-token` and higher-level token fixture crates.
