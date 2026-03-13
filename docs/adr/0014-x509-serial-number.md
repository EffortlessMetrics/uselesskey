# ADR-0014: X.509 Serial Number Policy

## Status
Accepted

## Context
X.509 serial numbers must be positive integers. Some parsers reject negative serial numbers (high bit set), causing test failures.

## Decision
X.509 certificate serial numbers are 16 bytes generated from RNG with the high bit cleared to ensure positive values.

- Length: 16 bytes (128 bits)
- High bit: Always cleared (`bytes[0] &= 0x7F`)
- Deterministic when seeded, random when not

## Consequences

**Positive:**
- 16 bytes provides sufficient uniqueness for test fixtures
- High bit cleared ensures serial numbers are always positive
- Compatible with all X.509 parsers

**Negative:**
- Slightly less entropy than full 16 bytes
- Not RFC 5280 maximum (20 bytes), but sufficient for tests

## Alternatives Considered
- **Full 20 bytes (RFC maximum):** Unnecessary for test fixtures
- **Sequential counters:** Requires global state, not thread-safe
- **Random without high-bit clear:** May produce negative values that some parsers reject
