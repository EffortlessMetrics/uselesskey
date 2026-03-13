# ADR-0012: Length-Prefixed Hashing for Field Concatenation

## Status
Accepted

## Context
When hashing multiple fields together (e.g., for seed derivation), concatenated fields like `"ab" + "c"` and `"a" + "bc"` would produce the same hash without length prefixes, breaking determinism guarantees.

## Decision
Each field is prefixed with its 32-bit big-endian length before hashing.

- Format: `[len_bytes: u32 BE][field_bytes]` for each field
- Used throughout derivation pipeline (X.509 base time, seed derivation)
- Test coverage proves `"a"+"bc"` ≠ `"ab"+"c"`

## Consequences

**Positive:**
- Field boundaries are preserved unambiguously
- Hash is deterministic regardless of field content
- No delimiter collision issues

**Negative:**
- 4 bytes overhead per field
- Requires knowing field length before hashing

## Alternatives Considered
- **Simple concatenation:** Vulnerable to boundary ambiguity
- **Delimiter-based (e.g., `|` or `0x00`):** Delimiter could appear in field content
- **JSON serialization:** Overhead, requires stable JSON ordering
