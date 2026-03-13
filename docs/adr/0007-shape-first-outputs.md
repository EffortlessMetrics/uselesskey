# ADR-0007: Shape-First Outputs

## Status
Accepted

## Context
Test authors typically need specific output formats (PEM, DER, JWK, tempfile paths) rather than raw cryptographic primitives.

## Decision
Fixture types expose shape-based output methods, not crypto primitives:

- `private_key_pkcs8_pem()` → PEM string
- `public_key_spki_der()` → DER bytes
- `to_jwk()` → JWK value
- `to_tempfile()` → TempArtifact with path

Users request the shape they need; the fixture handles serialization.

## Consequences

**Positive:**
- Ergonomic API for test authors
- Format conversion is encapsulated
- Easy to add new output shapes without breaking changes

**Negative:**
- More methods per fixture type
- Some shapes may not be available for all key types

## Alternatives Considered
- **Expose crypto primitives:** Leaks implementation details, more verbose
- **Single output format:** Doesn't match diverse test needs
