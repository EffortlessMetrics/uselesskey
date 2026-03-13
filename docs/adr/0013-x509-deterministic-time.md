# ADR-0013: X.509 Deterministic Time Derivation

## Status
Accepted

## Context
Tests need stable certificate validity periods across runs. Using actual time would cause tests to fail unpredictably as certificates expire.

## Decision
X.509 certificate timestamps are derived deterministically by hashing identity fields and mapping the hash to a day offset from a fixed epoch (2025-01-01).

- Epoch: `2025-01-01 00:00:00 UTC` (Unix: 1735689600)
- Validity window: 365 days from derived base time
- Day offset: Derived from first hash bytes modulo 365

## Consequences

**Positive:**
- Certificates always valid within test window
- Same identity produces same timestamps across runs
- Tests remain valid for years without time-based failures

**Negative:**
- Certificates have artificial timestamps
- Not suitable for production certificate generation

## Alternatives Considered
- **Fixed timestamp:** All certificates have same time, unrealistic
- **Random time:** Non-deterministic, breaks cacheability
- **Monotonic counter:** Requires global state, not thread-safe
