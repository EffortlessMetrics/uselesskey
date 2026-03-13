# ADR-0021: Publish Order Orchestration

## Status
Accepted

## Context
The workspace has 32 published crates with dependencies between them. Publishing in wrong order causes failures. crates.io doesn't support atomic multi-crate publishes.

## Decision
Publish order is manually maintained in xtask with:
- Hardcoded order respecting dependency graph
- Retry logic with exponential backoff
- State persistence for partial publishes
- Indexing delays between crates

Order: leaf crates → core aggregate → algorithm crates → adapters → facade

## Consequences

**Positive:**
- Reproducible publish process
- Recovery from partial failures
- Clear dependency ordering

**Negative:**
- Manual maintenance when adding crates
- Risk of order becoming stale
- Requires coordination across 32 crates

## Alternatives Considered
- **Automated dependency resolution:** Complex, error-prone for dev-dependencies
- **Single monolith:** Defeats microcrate architecture
- **Release-plz automation:** Used but still requires order specification
