+++
id = "USELESSKEY-SPEC-0001"
kind = "spec"
title = "Source-of-truth model"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = []
linked_plan = "plans/spec-system/implementation-plan.md"
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0001: Source-of-Truth Model

## Problem

`uselesskey` makes secret-shaped, certificate-shaped, token-shaped, and
scanner-sensitive fixture material for tests. That product surface needs public
claims that are precise enough for users, maintainers, release operators, and
agents to audit without relying on chat history.

The repo already has README badges, PR evidence, release checks, generated
receipts, and task-first docs. Without a source-of-truth model, those artifacts
can drift into duplicated prose:

- README claims can outpace the proof commands behind them.
- PR evidence can be mistaken for a repo-scoped public badge.
- Release proof can be hard to map back to the claim it proves.
- Agent prompts can keep repeating stale lane instructions after the repo moves
  on.

This spec defines the jobs of each source-of-truth artifact so later specs,
plans, ledgers, and tooling can validate the system consistently.

## Behavior

Repository truth is split by artifact job:

| Artifact | Owns | Does not own |
| --- | --- | --- |
| `README.md` | First-hour product truth, stable public entry points, compact badge masthead | Full proof matrix or active lane state |
| `CHANGELOG.md` | Release truth for shipped versions | Future work or active agent instructions |
| Proposal | Why a lane exists, users, value, alternatives, success criteria | Detailed acceptance mechanics or enforcement |
| Spec | Behavior contract, explicit non-goals, acceptance, required evidence, CI proof | PR queue management or narrative rationale |
| ADR | Durable architecture decision and consequences | Task breakdown or full implementation plan |
| Plan | PR sequence, validation commands, rollback, closeout shape | Product truth or durable architecture choice |
| Active goal manifest | Current agent lane state, linked specs, work items, proof commands | Historical closeout or public user docs |
| Claim ledger | Public claim to proof-command, artifact, docs, and release-lane mapping | Long-form explanation |
| Handoff / learning | What changed, evidence, remaining work, durable lessons | Active execution instructions |
| Receipt / generated endpoint | Machine-readable proof output or public Shields endpoint | Human rationale or product positioning |

The source-of-truth chain for public promises is:

```text
README claim
  -> claim ledger entry
    -> spec
      -> proof command
        -> generated artifact / badge / receipt
          -> release-evidence lane
            -> task-first user doc
              -> active goal manifest or archived closeout
```

Specs define behavior. Plans define sequencing. Active goal manifests define
current execution. Receipts prove claims.

Accepted specs must use TOML front matter with stable IDs and the required
sections from `docs/templates/spec.md`. Status values are limited to:

```text
proposed
accepted
implemented
superseded
archived
```

Public claim text should prefer concrete boundaries over broad trust language.
For example, `scanner-safe fixtures` means repository automation found no
committed secret-shaped fixture blobs under repo policy. It does not mean every
encoded export is safe to commit, and it does not imply production key
management or cryptographic assurance.

PR evidence and README badges must stay scope-separated:

- README badges are repo-scoped public trust markers.
- PR evidence is diff-scoped reviewer and agent feedback.
- Diff-scoped artifacts must not be republished as public README badges.

## Non-goals

This spec does not add new fixture profiles, TLS behavior, mTLS, revocation,
certificate-transparency coverage, browser trust-store behavior, or adapter
helpers.

This spec does not change crate APIs, crate publishing shape, dependency policy,
or feature selection.

This spec does not claim `cargo xtask spec-check` enforcement exists yet. It
defines the model that `spec-check` must validate after that command is added.

This spec does not make PR-scoped `ripr` evidence blocking. PR evidence remains
advisory unless a later policy explicitly promotes a subset.

## Required Evidence

The first evidence layer is document inventory and drift checking:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

The enforcement layer is future work owned by `cargo xtask spec-check`. Once
implemented, it must validate:

- required source-of-truth directories exist;
- TOML front matter parses;
- IDs are unique;
- `kind` matches the artifact directory;
- status values are allowed;
- linked proposal/spec/ADR IDs exist;
- accepted specs include the required sections;
- active goal work items link to existing specs and plans;
- claim-ledger entries include at least one proof command.

When stable, `spec-check` must be wired into docs evidence, PR evidence, and
release evidence.

## Acceptance

This spec is accepted when:

- it defines the source-of-truth artifact jobs used by the repo;
- it defines the public-claim traceability chain;
- it separates repo-scoped public badges from diff-scoped PR evidence;
- it identifies the required future `spec-check` validation contract;
- it avoids claiming enforcement before tooling exists.

This spec is implemented when:

- `cargo xtask spec-check` validates the source-of-truth artifacts;
- `cargo xtask spec-check --strict` is available for release lanes;
- `cargo xtask spec-check --format json` is available for receipts;
- docs and PR evidence run `spec-check`;
- patch and minor release evidence include `spec-check`.

## Acceptance Examples

Example: README badge claim.

```text
README ripr+ badge
  -> generated endpoint under badges/ripr-plus.json
  -> generated evidence endpoint spec
  -> cargo xtask badges --check
  -> docs/VERIFICATION.md
```

Example: scanner-safe fixture claim.

```text
README scanner-safe badge
  -> claim-ledger entry
  -> scanner-safe boundary docs
  -> cargo xtask scanner-safe-reference --check
  -> cargo xtask no-blob
  -> cargo xtask badges --check
```

Example: TLS contract pack.

```text
TLS how-to and README surface
  -> contract-pack spec
  -> cargo xtask bundle-proof --profile tls
  -> release evidence row
  -> docs/how-to/test-tls-chain-validation.md
```

Example: agent work.

```text
Codex lane instruction
  -> .uselesskey/goals/active.toml
  -> linked proposal/spec/plan
  -> validation commands listed per work item
```

## Test Mapping

Current docs-only checks cover formatting, documentation inventory, and typo
quality:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Future `spec-check` tests must cover front matter parsing, ID uniqueness, status
validation, linked artifact resolution, required spec sections, active goal
links, and claim-ledger proof-command presence.

## Implementation Mapping

The source-of-truth model is owned by these paths:

- `docs/README.md` indexes the human documentation system.
- `docs/proposals/` stores why-level lane proposals.
- `docs/specs/` stores behavior and proof contracts.
- `docs/adr/` stores durable architecture decisions.
- `docs/status/` stores public claim and support-tier indexes.
- `plans/` stores implementation sequencing.
- `.uselesskey/goals/` stores machine-readable active agent state.
- `policy/claim-ledger.toml` maps public claims to proof.
- `policy/spec-ledger.toml` may later record source-of-truth policy state.
- `xtask` owns `spec-check` once implemented.

## CI Proof

Before `spec-check` exists, docs-only PRs that modify this model should run:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

After `spec-check` exists, source-of-truth PRs should additionally run:

```bash
cargo xtask spec-check
cargo xtask spec-check --format json
```

After release wiring, patch and minor release evidence should include:

```bash
cargo xtask spec-check --strict
```

## Metrics / Promotion Rule

This spec remains `accepted` until standalone `spec-check` exists and the first
claim-ledger entries are present.

It can move to `implemented` when `spec-check` is wired into docs evidence, PR
evidence, and release evidence, and the active spec-system lane has a closeout
or archived goal manifest.
