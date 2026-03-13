# ADR-0022: Adapter Feature Flags

## Status
Accepted

## Context
Adapter crates integrate with downstream crypto libraries that may support multiple algorithms. Users shouldn't pay for algorithms they don't use.

## Decision
Adapters expose per-key-type feature flags:
- Individual features: `rsa`, `ecdsa`, `ed25519`, `hmac`
- Convenience feature: `all` enables all key types
- Default: usually empty or minimal

## Consequences

**Positive:**
- Users only pull dependencies they need
- Reduces compile time and binary size
- Clear feature matrix per adapter

**Negative:**
- More complex Cargo.toml
- Feature combinatorics for testing
- Documentation burden

## Alternatives Considered
- **All-or-nothing:** Forces unnecessary dependencies
- **Per-algorithm crates:** Too many crates
- **Auto-detection:** Unpredictable, hard to debug
