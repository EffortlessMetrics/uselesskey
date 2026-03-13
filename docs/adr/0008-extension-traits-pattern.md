# ADR-0008: Extension Traits Pattern

## Status
Accepted

## Context
Adding new key types directly to the Factory would cause monolithic API growth and require changes to core for each new algorithm.

## Decision
Key type support is added via extension traits on `Factory`:

- `RsaFactoryExt` → `fx.rsa(label, spec)`
- `EcdsaFactoryExt` → `fx.ecdsa(label, spec)`
- `Ed25519FactoryExt` → `fx.ed25519(label, spec)`
- `HmacFactoryExt` → `fx.hmac(label, spec)`
- `TokenFactoryExt` → `fx.token(label, spec)`
- `PgpFactoryExt` → `fx.pgp(label, spec)`
- `X509FactoryExt` → `fx.x509_self_signed(label, spec)`

Each extension trait lives in its own crate.

## Consequences

**Positive:**
- Core Factory stays small
- New key types don't require core changes
- Users only import what they need
- Clear ownership boundaries

**Negative:**
- More crates to maintain
- Users must import extension traits explicitly

## Alternatives Considered
- **Monolithic Factory:** Would grow unbounded
- **Feature flags:** Still couples all key types to core crate
