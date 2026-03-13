# ADR-0005: Cache-by-Identity Strategy

## Status
Accepted

## Context
RSA key generation is expensive (especially for 4096-bit keys). Without caching, tests that repeatedly request the same fixture would regenerate keys each time, making test suites slow.

## Decision
Per-process cache keyed by `(domain, label, spec, variant)` using `DashMap` with `Arc<dyn Any + Send + Sync>` storage.

- Cache key is the full artifact identity tuple
- Storage is thread-safe via DashMap
- Values are Arc'd for cheap cloning
- Cache lives for the process lifetime

## Consequences

**Positive:**
- RSA keygen becomes cheap after first generation
- Tests can request same fixture multiple times without performance penalty
- Avoids need for committed fixture files

**Negative:**
- Memory usage grows with unique fixtures (acceptable for test usage)
- Cache invalidation is process-bound (acceptable for test usage)

## Alternatives Considered
- **No cache:** Too slow for RSA-heavy tests
- **File-based cache:** Secret scanners would detect cached key material
- **LRU with eviction:** Adds complexity without clear benefit for test workloads
