# ADR-0024: Bias-Free Base62 Generation

## Status
Accepted

## Context
Random Base62 strings are used for KIDs and tokens. Using modulo to map random bytes to 62 characters introduces bias for some byte values.

## Decision
Use rejection sampling to avoid modulo bias:
- Accept bytes in range `0..=247` (62 × 4)
- Reject bytes ≥ 248 and retry
- Bounded fallback to prevent hangs with pathological RNG

## Consequences

**Positive:**
- Uniform distribution of output characters
- No statistical bias in generated strings
- Deterministic behavior even with bad RNG

**Negative:**
- Slight performance overhead from rejection
- Non-constant time (variable retries)
- More complex than simple modulo

## Alternatives Considered
- **Simple modulo:** Introduces bias for characters 0-5
- **Larger alphabet:** Doesn't solve bias, changes charset
- **Fixed retries:** May fail or produce bias
