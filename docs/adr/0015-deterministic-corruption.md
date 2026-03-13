# ADR-0015: Deterministic Corruption Variant Selection

## Status
Accepted

## Context
Tests need reproducible negative fixtures. Random corruption would cause flaky tests and make debugging difficult.

## Decision
Negative fixture corruption strategies (PEM/DER) are selected deterministically by hashing the variant string and using the hash bytes to index into strategy options.

- PEM: `bytes[0] % 5` selects from 5 corruption strategies
- DER: `bytes[0] % 3` selects from 3 corruption strategies
- Truncation length: Derived from additional hash bytes

## Consequences

**Positive:**
- Same variant string always produces same corruption
- Tests remain deterministic and reproducible
- Simple API: just pass a variant string

**Negative:**
- Limited corruption variety per variant
- May not cover all edge cases

## Alternatives Considered
- **Fixed corruption per variant:** Requires maintaining explicit mapping
- **Random corruption:** Non-deterministic, breaks snapshot testing
- **User-specified strategy:** More verbose API
