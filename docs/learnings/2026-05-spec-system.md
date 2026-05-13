+++
id = "USELESSKEY-LEARNING-2026-05-spec-system"
kind = "learning"
title = "Public fixture claims need command-backed source of truth"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-13"
linked_proposal = "USELESSKEY-PROP-0001"
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

# Public Fixture Claims Need Command-Backed Source of Truth

## Trigger

The v0.8.0 release made `uselesskey`'s public surface cleaner and more useful,
especially around the TLS contract pack and generated badge endpoints. That
also made a risk visible: useful claims such as scanner-safe fixtures, contract
packs, and PR evidence can drift if they live only in README prose, CI logs, or
chat handoffs.

## What Changed

The repository now treats public fixture claims as traceable artifacts:

```text
README claim -> claim ledger -> spec -> proof command -> artifact or badge
-> release evidence -> user doc -> active or archived goal state
```

The lane added proposals, specs, ADRs, plan state, active goal state, a claim
ledger, and `cargo xtask spec-check` so future agents can discover the current
operating model from the repo.

## Evidence

- `policy/claim-ledger.toml` maps public claims to specs, commands, artifacts,
  and boundaries.
- `cargo xtask spec-check --strict` validates source-of-truth artifacts.
- `cargo xtask docs-sync --check` and `cargo xtask pr` include `spec-check`.
- `cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary`
  and `cargo xtask release-evidence --version 0.9.0 --dry-run --summary`
  include `spec-check --strict`.
- `.uselesskey/goals/archive/2026-05-spec-system.toml` records the completed
  lane state.

## Rule to Keep

Do not promote a README claim unless it has an explicit proof path or an
explicit advisory/experimental boundary. Public badges are repo-scoped front
panel signals; PR evidence is diff-scoped reviewer and agent feedback.

## Follow-up Artifacts

Future fixture profiles should start from `USELESSKEY-SPEC-0003` and a new
active goal manifest. Future public proof surfaces should update
`policy/claim-ledger.toml` before they appear in the README.
