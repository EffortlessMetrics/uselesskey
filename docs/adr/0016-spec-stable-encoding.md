# ADR-0016: Spec Stable Encoding with Versioning

## Status
Accepted

## Context
Specs are used as cache keys and for deterministic derivation. Changing the encoding would invalidate all caches and break determinism without warning.

## Decision
Spec types implement `stable_bytes()` methods that produce a canonical byte representation for hashing, with explicit version prefixes to allow breaking changes.

- Version prefix: Single byte at start of encoding
- Breaking changes: Bump version prefix
- Nested structures: Sorted and deduplicated for stability

## Consequences

**Positive:**
- Breaking changes to spec encoding require bumping version prefix
- Old fixtures remain valid until version bump
- Explicit documentation of encoding format in code

**Negative:**
- Manual implementation required (not derived)
- Must remember to bump version on changes

## Alternatives Considered
- **`#[derive(Hash)]`:** Unstable across Rust versions, doesn't handle nested structures consistently
- **JSON serialization:** Overhead, requires stable ordering
- **No versioning:** Breaking changes would silently corrupt existing fixtures
