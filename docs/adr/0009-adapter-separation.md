# ADR-0009: Adapter Separation

## Status
Accepted

## Context
Adapter crates integrate uselesskey with downstream crypto libraries (jsonwebtoken, rustls, ring, etc.). Versioning them together creates coupling issues.

## Decision
Adapter crates are separate crates (not features) to avoid coupling uselesskey's versioning to downstream crate versions:

- `uselesskey-jsonwebtoken` → `jsonwebtoken` integration
- `uselesskey-rustls` → `rustls` / `rustls-pki-types` integration
- `uselesskey-ring` → `ring` integration
- `uselesskey-rustcrypto` → RustCrypto integration
- `uselesskey-aws-lc-rs` → `aws-lc-rs` integration
- `uselesskey-tonic` → `tonic` gRPC TLS integration

Each adapter can be versioned independently based on downstream breaking changes.

## Consequences

**Positive:**
- Downstream breaking changes don't force uselesskey version bumps
- Users only depend on adapters they need
- Clear compatibility matrix per adapter

**Negative:**
- More crates to publish
- Coordination required for cross-adapter changes

## Alternatives Considered
- **Feature flags:** Would couple all adapters to uselesskey version
- **Single adapter crate:** Would require all downstream deps for any adapter use
