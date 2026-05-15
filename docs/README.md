# Documentation

See the [project README](../README.md) for a quick start.

This documentation follows the [Diátaxis framework](https://diataxis.fr/), organizing content by purpose:

## Architecture Decisions

Architecture Decision Records (ADRs) capture significant design choices and their rationale.

- [ADR Index](adr/README.md) — Overview and index of all decisions
- [0001-use-adr-template.md](adr/0001-use-adr-template.md) — ADR format and process
- [0002-seed-boundary-abstraction.md](adr/0002-seed-boundary-abstraction.md) — RNG boundary abstraction for v0.4
- [0003-order-independent-determinism.md](adr/0003-order-independent-determinism.md) — Order-independent derivation design
- [0004-microcrate-architecture.md](adr/0004-microcrate-architecture.md) — Microcrate decomposition strategy

## Source of Truth

Repository operating artifacts are split by job so public claims, proof, and
agent state do not drift into one document.

- [proposals](proposals/README.md) - Why a lane exists, who benefits, and what alternatives were considered
- [specs](specs/README.md) - What behavior is promised, not promised, and how it is proven
- [status](status/README.md) - Public claim, support tier, and proof mapping indexes
- [handoffs](handoffs/README.md) - Closeout notes and operator handoffs after a lane changes state
- [learnings](learnings/README.md) - Durable lessons from releases, incidents, and proof lanes
- [plans](../plans/README.md) - PR sequencing and rollback plans
- [active goals](../.uselesskey/goals/README.md) - Machine-readable current agent lane state
- [agent bootstrap](handoffs/agent-bootstrap.md) - Read order and validation defaults for agents resuming work

## How-to Guides

Task-oriented instructions for common workflows.

- [choose-lane.md](how-to/choose-lane.md) — Pick the cheapest correct lane first
- [start-here.md](how-to/start-here.md) — Pick a user job and copy the first command or dependency snippet
- [migration.md](how-to/migration.md) — Migrating between uselesskey versions
- [publishing.md](how-to/publishing.md) — Publishing crates to crates.io
- [release.md](how-to/release.md) — Cutting a release
- [choose-features.md](how-to/choose-features.md) — Choosing feature sets by need
- [downstream-fixture-policy.md](how-to/downstream-fixture-policy.md) — Policy pack for downstream bots and reviewers
- [adapter-template.md](how-to/adapter-template.md) — Scaffolding and validating new adapter crates
- [test-oidc-jwks-validation.md](how-to/test-oidc-jwks-validation.md) — Using the OIDC/JWKS contract pack in validator tests
- [test-jwt-negative-validation.md](how-to/test-jwt-negative-validation.md) — Using JWT-shaped negatives for policy rejection tests
- [generate-scanner-safe-k8s-secret.md](how-to/generate-scanner-safe-k8s-secret.md) — Exporting scanner-safe Kubernetes and Vault-shaped payloads
- [verify-uselesskey-public-claims.md](how-to/verify-uselesskey-public-claims.md) — Verifying badge, scanner-safe, contract-pack, claim-proof, and release-smoke claims
- [share-uselesskey-verification-pack.md](how-to/share-uselesskey-verification-pack.md) — Collecting metadata-only public-claim receipts for security and platform review

## Contributing

Repository operating rules for agents and maintainers.

- [pr-disposition.md](contributing/pr-disposition.md) — Reviewing keeper, duplicate, stale, declined, and automation PRs

## CI and Evidence

Validation lanes and the claim boundaries behind them.

- [VERIFICATION.md](VERIFICATION.md) — README badge meanings, generated endpoints, and PR evidence boundaries
- [coverage.md](ci/coverage.md) — Coverage workflow scope, artifacts, and advisory status
- [test-evidence-lanes.md](ci/test-evidence-lanes.md) — PR, targeted mutation, nightly mutation, and release evidence model

## Release

Release-candidate proof and public promise evidence.

- [evidence-matrix-v0.9.0.md](release/evidence-matrix-v0.9.0.md) — v0.9.0 command-backed claim, verification-pack, PR-lite, and webhook proof matrix
- [evidence-matrix-v0.7.0.md](release/evidence-matrix-v0.7.0.md) — v0.7.0 public fixture promise evidence matrix
- [v0.7.0-checklist.md](release/v0.7.0-checklist.md) — Release-governance issue map for v0.7.0 checklist lines
- [v0.7.0-category-notes.md](release/v0.7.0-category-notes.md) — Release note category map and draft-audit guidance for v0.7.0
- [post-release-audit.md](release/post-release-audit.md) — Post-publish verification checklist for public fixture promises
- [scanner-safe-bundle](../examples/scanner-safe-bundle/README.md) — Reference manifest, receipts, and Kubernetes/Vault payload shapes for the default bundle lane

## Explanation

Understanding-oriented material on design and direction.

- [architecture.md](explanation/architecture.md) — Workspace structure and crate map
- [public-surface.md](architecture/public-surface.md) — Supported public crates versus published internal implementation shards
- [roadmap.md](explanation/roadmap.md) — Future plans and priorities (Now/Next/Later framework)
- [requirements.md](explanation/requirements.md) — Problem statement and design requirements

## Reference

Specifications and formal definitions.

- [dependency-economics.md](reference/dependency-economics.md) — Current lane cost receipts
- [audit-surface.md](reference/audit-surface.md) — Current audit/island receipts
- [verification-badges.md](reference/verification-badges.md) — Generated README badge endpoint rules and boundaries
- [requirements-v0.3.md](reference/requirements-v0.3.md) — v0.3 acceptance specification
- [requirements-v0.4.md](reference/requirements-v0.4.md) — v0.4 RNG boundary refactor specification
- [failure-atlas.md](reference/failure-atlas.md) — Failure classes covered by protocol-shaped negative fixtures

## Internal

Historical planning artifacts (not user-facing).

- [summary.md](internal/summary.md)
- [bdd-test-coverage-analysis.md](internal/bdd-test-coverage-analysis.md)
- [bdd-scenarios-implementation-plan.md](internal/bdd-scenarios-implementation-plan.md)
- [pr-bundle-reduction.md](internal/pr-bundle-reduction.md)
- [test-architecture-diagram.md](internal/test-architecture-diagram.md)
