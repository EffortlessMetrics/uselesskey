# ADR-0017: Seed Debug Redaction

## Status
Accepted

## Context
Seeds are 32-byte values that, if leaked, would allow reconstruction of all deterministic fixtures. Accidental logging could expose test fixtures.

## Decision
The `Seed` type implements `Debug` by redacting all bytes, displaying only `"Seed(**redacted**)"`.

- Debug output: Always `"Seed(**redacted**)"`
- Key material: Also redacted in Debug output (shows only lengths)
- Intentional access: Use `seed.bytes()` method when needed

## Consequences

**Positive:**
- Debug output never exposes seed material
- Accidental logging is safe
- Tests can still inspect seed bytes via `seed.bytes()` when needed

**Negative:**
- Debug output less useful for debugging seed issues
- Must use explicit methods to inspect seed material

## Alternatives Considered
- **Full debug output:** High risk of accidental leakage
- **Partial redaction:** Still risks exposing sensitive patterns
- **No Debug impl:** Inconvenient for debugging other issues
