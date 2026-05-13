+++
id = "USELESSKEY-PLAN-0002"
kind = "plan"
title = "Spec-system lane closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
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
+++

# Spec-System Lane Closeout

## Current State

The spec-system lane is implemented. `uselesskey` now has a source-of-truth
model for proposals, specs, ADRs, plans, active goals, claim ledgers, generated
badge endpoints, PR review evidence, and release evidence lanes.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-spec-system.toml`. The root
`.uselesskey/goals/active.toml` also records the lane as archived until a new
active lane is selected.

## Implemented Surface

- `USELESSKEY-PROP-0001` explains why the spec-governed fixture-platform lane
  exists.
- `USELESSKEY-SPEC-0001` through `USELESSKEY-SPEC-0007` define source of truth,
  public claims, contract-pack profiles, generated evidence endpoints, agent
  lane state, release evidence lanes, and PR review evidence.
- `USELESSKEY-ADR-0001` through `USELESSKEY-ADR-0004` capture durable platform
  choices for contract packs, command-backed claims, active goals, and README
  badge scope.
- `policy/claim-ledger.toml` maps public claims to proof commands, artifacts,
  and boundaries.
- `cargo xtask spec-check` validates the source-of-truth artifacts and claim
  ledger.
- `cargo xtask docs-sync --check`, `cargo xtask pr`, and release-evidence dry
  runs include `spec-check`.

## Proof

The final lane proof is:

```bash
cargo xtask badges --check
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask pr
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
```

## Non-Goals Held

This lane did not add new fixture profiles, TLS mTLS/revocation/CT behavior,
shipper migration work, no-panic cleanup, dependency churn, compatibility-shim
churn, or unrelated SRP refactors.

## Next Safe Action

Start the next product or proof lane by creating a new active goal manifest.
The archived spec-system manifest is historical state, not active instructions.
