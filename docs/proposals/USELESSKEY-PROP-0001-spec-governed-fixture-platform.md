+++
id = "USELESSKEY-PROP-0001"
kind = "proposal"
title = "Spec-governed fixture platform"
status = "proposed"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_specs = [
  "USELESSKEY-SPEC-0001",
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0004",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0007",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
linked_plan = "plans/spec-system/implementation-plan.md"
+++

# USELESSKEY-PROP-0001: Spec-Governed Fixture Platform

## Problem

`uselesskey` makes realistic, secret-shaped fixture material for tests. That is
useful because users need keys, certificates, tokens, bundles, and negative
cases that exercise real parser and validator paths without committing real
secrets or long-lived fixture blobs.

The same niche is easy to overstate. A scanner-safe fixture claim is not the
same thing as production key management. A generated TLS contract pack is not a
promise about every browser trust-store, revocation, CT, or deployment behavior.
A `ripr+` badge is not coverage, mutation adequacy, or correctness proof.

The repo already has real checks, release receipts, generated badge endpoints,
task-first docs, and PR evidence. The missing product layer is traceability:
public claims should map to specific proof commands, artifacts, docs, release
lanes, and current agent state instead of relying on README wording or chat
history.

## Users and Surfaces

The primary users are Rust test authors who want deterministic fixtures without
committed secret-shaped blobs. They touch the crate through README examples,
crate docs, feature selection, adapter crates, and how-to guides.

Platform and security teams use `uselesskey` as a policy pattern: generate
scanner-safe test material, prove the repo does not commit fixture blobs, and
keep the boundary between fake fixtures and production security explicit.

CI maintainers and release operators need commands that answer whether a public
claim is still true. They should be able to run one proof command or inspect one
receipt without reconstructing intent from prior PR discussion.

Agents such as Codex need a current repo-owned control plane. They should read
`.uselesskey/goals/active.toml` and linked proposals, specs, and plans instead
of carrying stale lane rules through chat.

## Success Criteria

The lane succeeds when public claims are command-backed:

- README badge and docs claims map to entries in `policy/claim-ledger.toml`.
- Claim-ledger entries identify proof commands, generated artifacts, user docs,
  and release evidence lanes.
- Accepted specs define behavior, non-goals, required evidence, acceptance,
  implementation ownership, and CI proof.
- ADRs capture durable architecture choices behind contract packs,
  command-backed claims, active goal manifests, and badge boundaries.
- `.uselesskey/goals/active.toml` identifies the current lane, linked specs,
  plans, work items, and proof commands for agents.
- `cargo xtask spec-check` validates source-of-truth artifacts before it is
  wired into PR and release evidence.
- Release evidence includes spec-check after the command has settled.

## Proposed Shape

Add a small source-of-truth system using Markdown artifacts with TOML front
matter and stable IDs:

- Proposals explain why a lane exists, who benefits, alternatives, and success
  criteria.
- Specs define behavior contracts, boundaries, acceptance, evidence, and CI
  proof.
- ADRs record durable architecture decisions that should outlive one PR.
- Plans define PR sequence, proof commands, rollback, and handoff shape.
- Active goal manifests define current agent state and stop stale prompt drift.
- Policy ledgers map public claims to proof commands, artifacts, docs, and
  release evidence.
- Handoffs and learnings record closeout and durable lessons after a lane
  changes state.

Keep README as the front panel, not the dashboard. Badge rows stay small and
repo-scoped:

```text
CI | Codecov | ripr+ | scanner-safe
Release | crates.io downloads | docs.rs
MSRV | license
```

Detailed PR evidence remains diff-scoped and belongs in summaries, annotations,
and artifacts. Generated badge endpoints remain committed Shields endpoint JSON
under `badges/` and are refreshed by `cargo xtask badges`.

## Alternatives Considered

README-only claims are easy to read but hard to audit. They do not tell users
which command proves a claim or where the release receipt lives.

CI-only proof is too implicit. A green workflow can prove many things, but users
and agents still need to know which check backs which public promise.

Free-form docs scale poorly across long-running lanes. Without IDs, front
matter, and ledgers, later agents have to infer current state from prose.

A heavyweight spec framework would add more ceremony than the crate needs. The
repo needs parseable Markdown, TOML ledgers, and xtask checks, not a CMS.

Putting PR-scoped `ripr` artifacts into README badges would mix two scopes.
README badges must be repo-scoped public trust markers; PR evidence should stay
diff-scoped and advisory unless a later policy explicitly promotes it.

## Specs to Create or Update

- `USELESSKEY-SPEC-0001`: Source-of-truth model
- `USELESSKEY-SPEC-0002`: Public claim ledger
- `USELESSKEY-SPEC-0003`: Contract-pack profile requirements
- `USELESSKEY-SPEC-0004`: Generated evidence endpoints
- `USELESSKEY-SPEC-0005`: Agent lane state
- `USELESSKEY-SPEC-0006`: Release evidence lanes
- `USELESSKEY-SPEC-0007`: PR review evidence

## Architecture Decisions Needed

- `USELESSKEY-ADR-0001`: Contract packs are proof-backed fixture profiles
- `USELESSKEY-ADR-0002`: Public claims require command-backed evidence
- `USELESSKEY-ADR-0003`: Repo goals are the agent control plane
- `USELESSKEY-ADR-0004`: README badges are a front panel, not a dashboard

## Implementation Campaign Shape

Use small, reviewable PRs:

1. Add this proposal.
2. Add source-of-truth and public claim-ledger specs.
3. Add the claim ledger and current public-claim status page.
4. Add contract-pack and generated-evidence endpoint specs and ADRs.
5. Add active goal manifest and implementation plan.
6. Add standalone `cargo xtask spec-check`.
7. Wire `spec-check` into docs and PR evidence after it proves stable.
8. Wire `spec-check` into patch and minor release evidence.
9. Close out the lane with a learning record and archived goal manifest.

## Evidence Plan

Initial PRs are docs-only and should prove formatting, docs inventory, and typo
cleanliness:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

The first command-backed phase adds:

```bash
cargo xtask spec-check
cargo xtask spec-check --strict
cargo xtask spec-check --format json
```

The final lane proof should include:

```bash
cargo xtask badges --check
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask pr
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
```

The proof commands are part of the expected end state, not claims made by this
proposal PR.

## Risks

The source-of-truth system can become paperwork if it records intentions without
proof commands. Specs must stay tied to artifacts, command output, and release
evidence.

The badge row can drift into badge theater if new badges are added without a
stable generated endpoint and documented boundary.

Agents can still drift if active goals are written once and never checked.
`spec-check` must eventually validate active work items against existing
non-superseded artifacts.

The `ripr+` count may be high while policy is being calibrated. Hiding it would
weaken the proof model; the right response is stable accounting, clear
boundaries, and focused reduction over time.

## Non-goals

This lane does not add new bundle profiles.

This lane does not add TLS mTLS, revocation, CT, browser trust-store behavior,
or new TLS adapter helpers.

This lane does not re-migrate anything to `shipper`.

This lane does not start the no-panic burndown.

This lane does not do compatibility-shim churn, dependency churn, or unrelated
SRP refactors.

This lane does not enable more direct writes to `main`. Badge automation may
open refresh PRs, but generated endpoint updates stay reviewable.

## Exit Criteria

The proposal is done when the spec-system lane has an accepted source-of-truth
model, a public claim ledger, contract-pack and badge endpoint specs, active
agent state, standalone `spec-check`, PR and release-evidence wiring, and a
closeout record that archives or updates the active goal.

The repo should then answer public claim questions from its own artifacts:

```text
README claim -> claim ledger -> spec -> proof command -> artifact or badge
-> release evidence -> user doc -> active goal or archived closeout
```
