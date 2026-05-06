# ADR-0028: Workspace Public Surface Policy

## Status

Accepted

## Context

`xtask` now publishes a long, explicit crate list (`PUBLISH_CRATES`) and release automation relies on that list as the only source of truth.

Without explicit policy, publishable/crate-intent confusion creates two hazards:

- accidental drift between manifests, release tooling, and public expectations
- incremental expansion of publish surface without explicit cost review

## Decision

The workspace crate policy is deliberately split into three categories:

1. **Public support promise**
   - Crates users are meant to depend on directly.
   - Includes the facade, fixture-family crates, adapter crates, operator
     surface, and test-infrastructure surfaces with distinct downstream jobs.
   - Must have complete crates.io and docs.rs metadata and pass preflight checks.
   - Must remain semver-governed according to the support matrix.
2. **Published internal**
   - Crates explicitly listed in `PUBLISH_CRATES` in `xtask/src/main.rs`.
   - Published for current release-graph or workspace-compatibility reasons, but
     not recommended as direct user dependencies.
   - Marked `experimental`, `repo-internal`, or equivalent in
     `docs/metadata/workspace-docs.json`.
   - Should point users to `uselesskey`, fixture-family crates, or adapter
     crates.
   - Must have complete crates.io and docs.rs metadata and pass preflight checks.
   - Prefer collapsing into SRP modules under the owning public crate when a
     release plan can do so without breaking current dependency constraints.
3. **Workspace-only internal**
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
  - `docs/architecture/public-surface.md`
  - smoke/integration coverage
- run `cargo xtask publish-preflight` and `cargo xtask publish-check` in PR scope
- add post-release verification for crates.io + docs.rs in the release checklist

For removing or deprecating a public crate:

- set `publish = false` when it should no longer be externally consumable
- remove it from `PUBLISH_CRATES`
- keep internal references updated so dependency edges remain valid
- record rationale in changelog and ADR history

For demoting a published internal crate into a module:

- choose one owner crate for the behavior
- preserve deterministic fixture output compatibility
- keep user-facing re-exports only through supported public surfaces
- update the support matrix metadata, publish tooling, and public-surface map in
  the same PR

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
