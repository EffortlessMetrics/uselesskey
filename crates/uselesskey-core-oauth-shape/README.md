# uselesskey-core-oauth-shape

SRP microcrate for deterministic OAuth access-token **shape** generation.

This crate produces JWT-looking `header.payload.signature` strings for test
fixtures. It is intentionally shape-only: it does not sign or verify tokens.
