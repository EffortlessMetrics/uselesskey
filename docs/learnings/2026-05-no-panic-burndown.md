+++
id = "USELESSKEY-LEARNING-2026-05-no-panic-burndown"
kind = "learning"
title = "No-panic progress needs a stage between advisory and deny"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-13"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0005",
]
linked_adrs = []
linked_plan = "plans/no-panic-burndown/implementation-plan.md"
+++

# No-Panic Progress Needs a Stage Between Advisory and Deny

## Trigger

Issue #575 showed that the repo had already moved past an advisory-only
panic-family posture: `cargo xtask check-no-panic-family` was running in
`no-new-debt` mode, but 150 unreceipted new-debt sites still blocked the lane.

## What Changed

The lane burned down those new-debt sites without resetting the baseline.
Test setup migrated toward fallible helper APIs, production-path findings were
removed or receipted, and the baseline was refreshed only after the checker was
clean.

The repo now records this as Stage A.5:

```text
warn-level Clippy panic-family lints
+ semantic no-panic checker in no-new-debt mode
+ historical baseline still active
```

## Evidence

- `cargo xtask check-no-panic-family` exits 0 with 0 new-debt, 0 stale
  allowlist entries, and 0 expired allowlist entries.
- `policy/no-panic-allowlist.toml` carries receipted production-path
  invariants.
- `policy/no-panic-baseline.toml` was refreshed with
  `cargo xtask no-panic baseline`, not `--reset`.
- `policy/clippy-lints.toml` records Stage A.5 instead of pretending the repo is
  ready for Stage C.

## Rule to Keep

Do not equate "0 new debt" with "panic-family lint deny is ready." Stage C
requires historical baseline debt to be removed or receipted so the allowlist is
the authoritative ledger.

## Follow-up Artifacts

Future no-panic work should update:

- `policy/no-panic-allowlist.toml` when an exception is intentionally retained;
- `policy/no-panic-baseline.toml` with `cargo xtask no-panic baseline` after a
  deliberate burndown PR;
- `docs/NO_PANIC_POLICY.md` and `policy/clippy-lints.toml` when the rollout
  stage changes;
- `.uselesskey/goals/active.toml` and the linked implementation plan for active
  lane state.
