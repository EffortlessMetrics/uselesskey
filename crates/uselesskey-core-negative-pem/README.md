# uselesskey-core-negative-pem

PEM-corruption helpers for deterministic and deterministic-shape negative fixtures.

## Responsibilities

- Corrupt PEM-like strings with a small, explicit set of mutation modes.
- Provide deterministic corruption selection from a variant label.
- Keep implementation `no_std`-compatible and focused on shape-only text mutation.

## Public API

- `CorruptPem`
- `corrupt_pem`
- `corrupt_pem_deterministic`
