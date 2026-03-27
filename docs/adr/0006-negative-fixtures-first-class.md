# ADR-0006: Negative Fixtures First-Class

## Status
Accepted

## Context
Testing error handling requires invalid/corrupt key material. Making negative fixtures an afterthought leads to incomplete test coverage.

## Decision
Negative fixtures are first-class API citizens with dedicated types and variants:

- `CorruptPem` enum with variants: `BadHeader`, `BadFooter`, `MissingDashes`, `CorruptBase64`, `Truncated`
- `corrupt_der_deterministic()` for reproducible DER corruption
- `"mismatch"` variant for keypair mismatches
- X.509 negative fixtures: expired, not-yet-valid, hostname mismatch,
  unknown CA, intermediate CA/key-usage violations, revoked

## Consequences

**Positive:**
- Error path testing is ergonomic
- Deterministic corruption enables reproducible tests
- Complete coverage of failure modes

**Negative:**
- More API surface to maintain
- Corruption variants must remain stable for determinism

## Alternatives Considered
- **Ad-hoc corruption:** Not reproducible, hard to test specific failure modes
- **External fixture files:** Triggers secret scanners
