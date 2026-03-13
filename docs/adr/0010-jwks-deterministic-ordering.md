# ADR-0010: JWKS Deterministic Ordering by kid

## Status
Accepted

## Context
JWKS is a JSON array where key order matters for deterministic output. Without stable ordering, test snapshots would change unpredictably when keys are generated in different orders.

## Decision
JWKS entries are sorted lexicographically by `kid`, with insertion order as tiebreaker for duplicate `kid` values.

- Primary sort: `kid` lexicographic comparison
- Secondary sort: insertion index for duplicate `kid` values
- `JwksBuilder` provides fluent API for building ordered JWKS

## Consequences

**Positive:**
- JWKS output is deterministic regardless of key generation order
- Duplicate `kid` values preserve insertion order for testing edge cases
- Snapshot tests remain stable

**Negative:**
- Requires tracking insertion order
- Slight overhead for sorting

## Alternatives Considered
- **Unsorted (insertion order only):** Non-deterministic across test runs
- **Sort by key type:** Doesn't provide stable ordering for multiple keys of same type
- **Sort by creation timestamp:** Requires additional state tracking
