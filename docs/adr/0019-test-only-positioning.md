# ADR-0019: Test-Only Positioning

## Status
Accepted

## Context
Existing solutions either lack determinism, commit key material (triggering secret scanners), or require external tools. This crate fills the gap for test fixtures specifically.

## Decision
Uselesskey is positioned as a test-fixture layer, not a production crypto library. This affects API design, documentation tone, and feature scope.

- API: Optimized for test ergonomics (one-liners, negative fixtures)
- Documentation: Emphasizes test-only use
- Scope: No production crypto expectations or guarantees
- Adapters: Separate crates to avoid version coupling

## Consequences

**Positive:**
- Clear positioning prevents misuse
- API optimized for test scenarios
- No production crypto audit burden

**Negative:**
- Not suitable for production key generation
- May lack features needed for production use

## Alternatives Considered
- **Full crypto library:** Competes with established crates, larger scope
- **Production-ready with audit:** Unnecessary overhead for test-only use case
- **CLI tool:** Less ergonomic for programmatic test generation
