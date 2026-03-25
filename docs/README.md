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

## How-to Guides

Task-oriented instructions for common workflows.

- [migration.md](how-to/migration.md) — Migrating between uselesskey versions
- [publishing.md](how-to/publishing.md) — Publishing crates to crates.io
- [release.md](how-to/release.md) — Cutting a release
- [choose-features.md](how-to/choose-features.md) — Choosing feature sets by need
- [adapter-template.md](how-to/adapter-template.md) — Scaffolding and validating new adapter crates

## Explanation

Understanding-oriented material on design and direction.

- [architecture.md](explanation/architecture.md) — Workspace structure and crate map
- [roadmap.md](explanation/roadmap.md) — Future plans and priorities (Now/Next/Later framework)
- [requirements.md](explanation/requirements.md) — Problem statement and design requirements

## Reference

Specifications and formal definitions.

- [requirements-v0.3.md](reference/requirements-v0.3.md) — v0.3 acceptance specification
- [requirements-v0.4.md](reference/requirements-v0.4.md) — v0.4 RNG boundary refactor specification

## Internal

Historical planning artifacts (not user-facing).

- [summary.md](internal/summary.md)
- [bdd-test-coverage-analysis.md](internal/bdd-test-coverage-analysis.md)
- [bdd-scenarios-implementation-plan.md](internal/bdd-scenarios-implementation-plan.md)
- [test-architecture-diagram.md](internal/test-architecture-diagram.md)
