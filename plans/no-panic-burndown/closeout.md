+++
id = "USELESSKEY-PLAN-0008"
kind = "plan"
title = "No-panic new-debt burndown closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0005",
]
linked_adrs = []
+++

# No-Panic New-Debt Burndown Closeout

## Current State

The no-panic new-debt burndown lane is implemented. `uselesskey` now runs the
semantic no-panic checker in `no-new-debt` mode with zero unreceipted new debt.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-no-panic-burndown.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `cargo xtask check-no-panic-family` exits 0 in `no-new-debt` mode.
- The new-debt count from issue #575 was burned down without
  `cargo xtask no-panic baseline --reset`.
- CLI and xtask panic-family test setup moved to fallible test-support helpers.
- Production-path new debt was either removed or moved into
  `policy/no-panic-allowlist.toml` with owner, classification, explanation, and
  expiry.
- `policy/no-panic-baseline.toml` was refreshed with
  `cargo xtask no-panic baseline` only after the checker was clean.
- `policy/clippy-lints.toml` now records Stage A.5: warn-level Clippy
  panic-family lints plus no-new-debt semantic enforcement.

## Remaining Policy Debt

Stage A.5 is not Stage C. The historical baseline still contains existing
panic-family debt, so Clippy panic-family lints remain at `warn` and the
semantic checker remains in `no-new-debt` mode.

The next no-panic lane should burn down or receipt historical baseline entries
until the allowlist can become the authoritative ledger. Only then should the
repo advance to Stage B or Stage C.

## Proof

The closeout proof is:

```bash
cargo test -p uselesskey-core
cargo test -p uselesskey-jwk
cargo test -p uselesskey-token
cargo xtask check-no-panic-family
cargo xtask check-lint-policy
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

## Non-Goals Held

This lane did not reset the baseline, weaken panic policy, flip Clippy
panic-family lints to `deny`, reclassify historical baseline debt as reviewed,
add fixture profiles, execute a release, migrate to shipper, add README badges,
or introduce dependency churn.

## Next Safe Action

Start the next lane from a fresh `.uselesskey/goals/active.toml` and linked
plan. The archived no-panic new-debt goal is historical state, not live
instructions.
