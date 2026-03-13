# ADR-0020: no_std Support Pattern

## Status
Accepted

## Context
Core crates may be used in embedded or WebAssembly environments where the standard library is not available. Supporting no_std increases the reach of the library.

## Decision
Core crates support no_std via feature flags, using conditional compilation:
- `#![cfg_attr(not(feature = "std"), no_std)]` at crate root
- `spin::Mutex` instead of `DashMap` when std is not available
- `alloc` crate for heap allocations in no_std mode

## Consequences

**Positive:**
- Core crates usable in embedded/wasm environments
- Broader ecosystem compatibility
- Forced discipline around std dependencies

**Negative:**
- Additional testing burden for no_std mode
- Performance difference between DashMap (concurrent) and spin::Mutex (blocking)
- Some features unavailable in no_std mode

## Alternatives Considered
- **std-only:** Limits use in embedded/wasm
- **Separate no_std crates:** Duplicates code, maintenance burden
- **Full no_std:** Limits functionality (no filesystem, etc.)
