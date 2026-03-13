# ADR-0018: No Unsafe Code Policy

## Status
Accepted

## Context
This is a test fixture library, not performance-critical crypto code. The benefits of unsafe code don't justify the risks for this use case.

## Decision
All crates in the workspace use `#![forbid(unsafe_code)]` to prohibit unsafe Rust code.

- Enforcement: Compile-time error on any `unsafe` block
- Scope: All crates in workspace
- No exceptions: Not even for performance optimizations

## Consequences

**Positive:**
- Code review is simpler (no unsafe audit needed)
- Reduces attack surface
- Clear safety guarantee for users

**Negative:**
- May limit optimization opportunities (acceptable for test fixtures)
- Some FFI interop patterns not available

## Alternatives Considered
- **Allow unsafe with audit:** Adds maintenance burden
- **`#![deny(unsafe_code)]`:** Allows `unsafe` with explicit `#[allow(unsafe)]`
- **No lint:** No enforcement
