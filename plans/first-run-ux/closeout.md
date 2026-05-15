+++
id = "USELESSKEY-PLAN-0014"
kind = "plan"
title = "First-run UX closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-15"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0008",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0010",
  "USELESSKEY-SPEC-0011",
  "USELESSKEY-SPEC-0012",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
+++

# First-Run UX Closeout

## Current State

The first-run UX and contract-pack adoption lane is implemented. `uselesskey`
now has a task-first front door that lets users pick a job, copy a command or
dependency snippet, generate a fixture, and find the proof boundary without
starting from the repo's internal ledgers.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-first-run-ux.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `docs/how-to/start-here.md` routes common user jobs to the first command or
  dependency snippet.
- `docs/contract-packs/README.md` presents scanner-safe, TLS, OIDC/JWKS, and
  webhook as visible contract-pack product units with generate, verify, proof,
  and boundary rows.
- The README opens with a smaller task-first path before deeper proof-system
  details.
- `uselesskey profiles` lists available bundle profiles with copyable generate,
  verify, proof, and verification-pack commands.
- `uselesskey profile <name> --explain` explains generated files, scanner-safe
  posture, proof commands, and claim boundaries for each profile.
- `USELESSKEY-SPEC-0012` defines the CLI proof-handoff boundary and keeps
  executable proof in allowlisted `xtask` surfaces until a safe reusable proof
  engine exists.
- `cargo xtask doctor` and `cargo xtask doctor --format json` diagnose local
  proof-environment readiness without conflating environment warnings with code
  failures.
- `cargo xtask user-path-smoke` exercises the documented first-run bundle paths,
  verifies each bundle, and builds a webhook-focused metadata-only verification
  pack.

## Proof

The closeout proof is:

```bash
cargo xtask user-path-smoke
cargo xtask doctor
cargo xtask docs-sync --check
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

## Non-Goals Held

This lane did not add a new fixture family, create a provider compatibility
matrix, add README badges, switch release tooling, start historical no-panic
baseline work, introduce dependency churn, or move raw generated fixture
payloads into committed reviewer artifacts.

## Follow-Up

Future product lanes should keep the same shape: users see task-first commands
and explicit boundaries first, while claim ledgers, specs, proof receipts, and
release evidence stay available for reviewers and maintainers who need them.

If a future CLI proof command is added, it should reuse a safe proof engine and
must not shell-evaluate claim-ledger command strings.
