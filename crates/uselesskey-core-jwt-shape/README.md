# uselesskey-core-jwt-shape

JWT-shaped OAuth access token primitives for `uselesskey`.

## Purpose

- Generate realistic `header.payload.signature` access-token shapes for tests.
- Keep OAuth/JWT-shape logic isolated from API-key and opaque bearer token helpers.
- Preserve deterministic output when driven by seeded RNGs.

This crate only models token **shape** and does not sign or validate JWTs.
