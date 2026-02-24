# uselesskey-core-token

Deterministic token-shape generation helpers for `uselesskey` fixture crates.

## Purpose

- Generate realistic API key, bearer token, and OAuth access-token shapes.
- Keep token formatting logic independent from factory/cache wiring.
- Provide stable helper APIs that adapter crates can reuse.

This microcrate only models token **shape**; it does not sign or validate tokens.
