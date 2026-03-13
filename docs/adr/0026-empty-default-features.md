# ADR-0026: Empty Default Features

## Status
Accepted

## Context
The facade crate can pull in many dependencies via default features. Users may not need all functionality and shouldn't pay for unused code.

## Decision
The facade crate has empty default features:
- `default = []`
- Users must explicitly enable: `rsa`, `ecdsa`, `token`, etc.
- Convenience feature `full` enables everything

## Consequences

**Positive:**
- Minimal dependency tree by default
- Users discover features explicitly
- Prevents accidental bloat

**Negative:**
- More verbose Cargo.toml for users
- "Why doesn't it work?" without features
- Documentation must emphasize feature selection

## Alternatives Considered
- **Default to common features:** Still forces unwanted deps
- **Default to all:** Defeats the purpose
- **Auto-detect:** Unpredictable, hard to debug
