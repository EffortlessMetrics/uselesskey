# ADR-0004: Microcrate Architecture

## Status

Accepted

## Context

uselesskey needs to support multiple cryptographic algorithms (RSA, ECDSA, Ed25519, HMAC) and integrate with multiple crypto backends (rustls, ring, RustCrypto, aws-lc-rs, jsonwebtoken). This creates several architectural challenges:

- **Dependency bloat**: Users only need one algorithm but would pull all dependencies
- **Version coupling**: Backend adapters have different release cycles than core
- **Feature explosion**: Monolithic feature flags become complex and error-prone
- **Compile times**: Building unused crypto code wastes developer time
- **Semantic versioning**: Changes to one backend shouldn't require bumping the entire crate

A traditional "all-in-one" crate with feature flags was considered but has significant downsides at scale.

## Decision

We adopt a microcrate architecture with the following structure:

### Core Crates

- **`uselesskey-core`**: Factory, derivation, caching, negative fixtures (no algorithm-specific code)
- **`uselesskey-core-jwk`**: Typed JWK/JWKS models with stable ordering semantics
- **`uselesskey-core-x509-spec`**: X.509 spec models and encoding helpers
- **`uselesskey-core-x509`**: X.509 negative-policy types plus re-exports

### Algorithm Crates (extension traits)

- **`uselesskey-rsa`**: `RsaFactoryExt` trait for RSA fixtures
- **`uselesskey-ecdsa`**: `EcdsaFactoryExt` trait for ECDSA (P-256/P-384) fixtures
- **`uselesskey-ed25519`**: `Ed25519FactoryExt` trait for Ed25519 fixtures
- **`uselesskey-hmac`**: `HmacFactoryExt` trait for HMAC fixtures
- **`uselesskey-token`**: `TokenFactoryExt` trait for API keys, bearer tokens
- **`uselesskey-pgp`**: `PgpFactoryExt` trait for OpenPGP key fixtures
- **`uselesskey-x509`**: `X509FactoryExt` trait for X.509 certificates

### Adapter Crates (backend integration)

- **`uselesskey-jsonwebtoken`**: `jsonwebtoken` crate integration
- **`uselesskey-rustls`**: `rustls` / `rustls-pki-types` integration
- **`uselesskey-ring`**: `ring` crate integration
- **`uselesskey-rustcrypto`**: RustCrypto ecosystem integration
- **`uselesskey-aws-lc-rs`**: `aws-lc-rs` crate integration
- **`uselesskey-tonic`**: `tonic` gRPC TLS integration

### Facade Crate

- **`uselesskey`**: Re-exports stable API from core and algorithm crates

### Extension Pattern

Algorithm support is added via extension traits on `Factory`:

```rust
// In uselesskey-rsa
pub trait RsaFactoryExt {
    fn rsa(&self, label: &str, spec: RsaSpec) -> RsaFixture;
}

// Users bring their own algorithm crates
use uselesskey::Factory;
use uselesskey_rsa::RsaFactoryExt;

let fx = Factory::deterministic(seed);
let key = fx.rsa("issuer", RsaSpec::rs256());
```

### Adapter Isolation

Adapter crates are separate crates (not features) to:

- Allow independent versioning
- Avoid coupling adapter updates to core releases
- Enable backend-specific dependencies without affecting others

## Consequences

### Positive

- **Minimal dependencies**: Users only pull what they need (e.g., just `uselesskey-ed25519`)
- **Independent versioning**: Adapters can bump for backend changes without affecting core
- **Faster compilation**: Smaller dependency graphs for typical use cases
- **Clear boundaries**: Each crate has a single, well-defined responsibility
- **Extensibility**: New algorithms or backends don't require modifying existing crates
- **Testing isolation**: Tests can target specific crates without full workspace

### Negative

- **Coordination overhead**: Changes across crates require multiple PRs or releases
- **Documentation complexity**: Need to explain which crates to use for which purpose
- **Version matrix**: Users must ensure compatible versions across crates
- **Publish complexity**: Must release in dependency order (handled by xtask)
- **More boilerplate**: Each crate needs its own Cargo.toml, CI config, etc.

## Alternatives Considered

### Single crate with features

One crate with features like `rsa`, `ecdsa`, `rustls`, etc.

**Rejected because**: Feature flag explosion; backend features conflict; compile times still high; version coupling remains.

### Separate repositories

Each adapter in its own repository.

**Rejected because**: Coordination nightmare; CI duplication; harder to ensure compatibility; release orchestration complexity.

### Core + bundled adapters

Core crate with optional adapter modules.

**Rejected because**: Still requires feature flags for adapters; doesn't solve version coupling; dependencies still pulled transitively.

### Trait-based abstraction

Define traits in core, implement in user code.

**Rejected because**: Too much boilerplate for users; defeats the "one dev-dependency" goal; requires users to understand internal architecture.
