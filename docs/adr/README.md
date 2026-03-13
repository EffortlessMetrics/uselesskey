# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the uselesskey project.

## What is an ADR?

An Architecture Decision Record is a document that captures an important architectural decision made along with its context and consequences. ADRs provide:

- **Historical context**: Why was a particular decision made?
- **Onboarding aid**: New contributors can understand the architecture quickly
- **Decision log**: A chronological record of significant architectural choices

## ADR Format

Each ADR follows this structure:

- **Status**: Accepted, Proposed, Deprecated, or Superseded
- **Context**: What is the issue or question being addressed?
- **Decision**: What is the change or approach being taken?
- **Consequences**: What are the positive and negative outcomes?
- **Alternatives Considered**: What other options were evaluated?

## Creating a New ADR

1. Copy `0001-use-adr-template.md` to a new file
2. Increment the number (use the next available sequence number)
3. Create a short, kebab-case title (e.g., `0005-add-new-feature.md`)
4. Fill in all sections
5. Submit with your pull request

### Naming Convention

```
NNNN-short-title.md
```

- `NNNN`: Zero-padded sequence number (0001, 0002, etc.)
- `short-title`: Brief, kebab-case description of the decision

## Index of ADRs

| Number | Title | Status | Date |
|--------|-------|--------|------|
| [0001](0001-use-adr-template.md) | Use ADR Template | Accepted | 2026-03-13 |
| [0002](0002-seed-boundary-abstraction.md) | Seed Boundary Abstraction | Accepted | 2026-03-13 |
| [0003](0003-order-independent-determinism.md) | Order-Independent Determinism | Accepted | 2026-03-13 |
| [0004](0004-microcrate-architecture.md) | Microcrate Architecture | Accepted | 2026-03-13 |
| [0005](0005-cache-by-identity.md) | Cache-by-Identity Strategy | Accepted | 2026-03-13 |
| [0006](0006-negative-fixtures-first-class.md) | Negative Fixtures First-Class | Accepted | 2026-03-13 |
| [0007](0007-shape-first-outputs.md) | Shape-First Outputs | Accepted | 2026-03-13 |
| [0008](0008-extension-traits-pattern.md) | Extension Traits Pattern | Accepted | 2026-03-13 |
| [0009](0009-adapter-separation.md) | Adapter Separation | Accepted | 2026-03-13 |
| [0010](0010-jwks-deterministic-ordering.md) | JWKS Deterministic Ordering by kid | Accepted | 2026-03-13 |
| [0011](0011-kid-generation-blake3.md) | KID Generation via BLAKE3 Truncation | Accepted | 2026-03-13 |
| [0012](0012-length-prefixed-hashing.md) | Length-Prefixed Hashing for Field Concatenation | Accepted | 2026-03-13 |
| [0013](0013-x509-deterministic-time.md) | X.509 Deterministic Time Derivation | Accepted | 2026-03-13 |
| [0014](0014-x509-serial-number.md) | X.509 Serial Number Policy | Accepted | 2026-03-13 |
| [0015](0015-deterministic-corruption.md) | Deterministic Corruption Variant Selection | Accepted | 2026-03-13 |
| [0016](0016-spec-stable-encoding.md) | Spec Stable Encoding with Versioning | Accepted | 2026-03-13 |
| [0017](0017-seed-debug-redaction.md) | Seed Debug Redaction | Accepted | 2026-03-13 |
| [0018](0018-no-unsafe-code.md) | No Unsafe Code Policy | Accepted | 2026-03-13 |
| [0019](0019-test-only-positioning.md) | Test-Only Positioning | Accepted | 2026-03-13 |
| [0020](0020-no-std-support.md) | no_std Support Pattern | Accepted | 2026-03-13 |
| [0021](0021-publish-order-orchestration.md) | Publish Order Orchestration | Accepted | 2026-03-13 |
| [0022](0022-adapter-feature-flags.md) | Adapter Feature Flags | Accepted | 2026-03-13 |
| [0023](0023-two-layer-adapter.md) | Two-Layer Adapter Pattern | Accepted | 2026-03-13 |
| [0024](0024-bias-free-base62.md) | Bias-Free Base62 Generation | Accepted | 2026-03-13 |
| [0025](0025-pr-scoped-ci.md) | PR-Scoped CI | Accepted | 2026-03-13 |
| [0026](0026-empty-default-features.md) | Empty Default Features | Accepted | 2026-03-13 |

## References

- [Documenting Architecture Decisions (Michael Nygard)](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
- [ADR GitHub Organization](https://adr.github.io/)
