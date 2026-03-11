# uselesskey-core-token-shape

Low-level token shape primitives for `uselesskey`.

## Purpose

- Generate deterministic and realistic API key shapes.
- Generate opaque bearer token shapes.
- Generate OAuth-like JWT-access-token shapes without signing.

This crate intentionally contains token-shape composition logic for API keys
and bearer tokens, and re-exports OAuth JWT-shape generation from
`uselesskey-core-oauth-shape`.
