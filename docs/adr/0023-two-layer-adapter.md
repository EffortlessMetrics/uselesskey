# ADR-0023: Two-Layer Adapter Pattern

## Status
Accepted

## Context
Adapters need to both convert types and build configurations. Mixing these concerns makes reuse difficult.

## Decision
Adapter crates separate concerns into two layers:
1. **PKI conversion layer** (`uselesskey-core-rustls-pki`): Type conversion traits
2. **Config building layer** (`uselesskey-rustls`): Config builders using conversion traits

## Consequences

**Positive:**
- PKI conversion reusable without config builders
- Independent evolution of layers
- Clear separation of concerns

**Negative:**
- More crates to maintain
- Users may need to understand both layers
- Slightly more complex imports

## Alternatives Considered
- **Single adapter crate:** Mixes concerns, harder to reuse
- **Trait-only adapters:** No convenience builders
- **Macro-based:** Less type-safe, harder to debug
