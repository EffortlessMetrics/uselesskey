# ADR-0028: Workspace Public Surface Policy

## Status

Accepted

## Context

`xtask` now publishes a long, explicit crate list (`PUBLISH_CRATES`) and release automation relies on that list as the only source of truth.

Without explicit policy, publishable/crate-intent confusion creates two hazards:

- accidental drift between manifests, release tooling, and public expectations
- incremental expansion of publish surface without explicit cost review

## Decision

The workspace public surface is deliberately split into two categories:

1. **Intentionally publishable**
   - Crates explicitly listed in `PUBLISH_CRATES` in `xtask/src/main.rs`.
   - Intended for external consumers and must remain semver-governed.
   - Must have complete crates.io and docs.rs metadata and pass preflight checks.
2. **Internal**
   - Crates not in `PUBLISH_CRATES`, including helper/test tooling crates, build infra, and local adapters.
   - Must set `publish = false` in `Cargo.toml`.

Review bar before adding a new publishable crate:

- submit a dedicated design rationale (e.g. ADR) and milestone/issue linkage
- show upstream/native demand and expected consumer maintenance burden
- place crate in a stable dependency slot in `PUBLISH_CRATES`
- add or update:
  - version policy in manifest
  - dependency snippets in release-facing docs
  - docs/metadata generated source
  - smoke/integration coverage
- run `cargo xtask publish-preflight` and `cargo xtask publish-check` in PR scope
- add post-release verification for crates.io + docs.rs in the release checklist

For removing or deprecating a public crate:

- set `publish = false` when it should no longer be externally consumable
- remove it from `PUBLISH_CRATES`
- keep internal references updated so dependency edges remain valid
- record rationale in changelog and ADR history

Release risk control:

- each additional publishable crate increases publish-set maintenance and release blast radius.
- adding crate count requires explicit maintainer sign-off and a milestone with release governance checkpoints.
- if a crate cannot be validated by release checks within current PR gates, it is rejected as publishable expansion.

## Consequences

### Positive

- Public surface changes become explicit, reviewable, and tied directly to release tooling.
- Release automation and dependency graphs stay aligned with documented intent.
- Consumers can rely on a stable and documented crate set.

### Negative

- There is friction to publish surface changes, intentionally delaying low-value experiments.
- Some potentially useful crates will remain internal until they pass formal review bar.

## Alternatives Considered

- **Maintain separate “publishable crates” docs and tooling lists**
  - **Rejected:** drift risk rises as the list changes.
- **Publish everything in workspace by default**
  - **Rejected:** operational risk and maintenance burden increase with no corresponding consumer benefit.
- **Rely on contributor discussion only**
  - **Rejected:** insufficient control for deterministic release and preflight automation.
