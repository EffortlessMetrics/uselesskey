+++
id = "USELESSKEY-PLAN-0006"
kind = "plan"
title = "PR-lite evidence ergonomics closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0010",
]
linked_adrs = []
+++

# PR-Lite Evidence Ergonomics Closeout

## Current State

The PR-lite evidence ergonomics lane is implemented. `uselesskey` now has a
bounded local PR evidence command and heavy-evidence routing receipts that make
targeted mutation decisions explicit.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-pr-lite-evidence.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `cargo xtask pr-lite` writes Markdown and JSON receipts under
  `target/pr-lite/`.
- PR-lite receipts distinguish local checks, skipped checks, hosted-only
  evidence, heavy-routing decisions, and claim boundaries.
- `cargo xtask mutants-pr --changed --explain` writes mutation-routing receipts
  under `target/xtask/mutation-routing/`.
- Mutation routing receipts include changed files, selected owner crates, RIPR
  severe-gap routing, label-sensitive hosted routing notes, selected commands,
  diff-filter availability, and fallback reasons.
- Diff-scoped mutation is used only when changed owner paths map cleanly to
  Rust hunks and the diff file can be generated and written.
- `--full-owner` mutation remains crate-scoped by design.
- `docs/handoffs/local-validation.md` defines how agents and contributors
  should report local, hosted, mutation, claim, and release evidence without
  overclaiming.

## Proof

The closeout proof is:

```bash
cargo test -p xtask pr_lite
cargo test -p xtask mutation_diff_filter
cargo test -p xtask mutation_command_for_crate
cargo xtask pr-lite
cargo xtask mutants-pr --changed --explain
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
cargo xtask pr
git diff --check
```

## Non-Goals Held

This lane did not add product behavior, public claims, new fixture profiles,
README badges, release execution, shipper migration work, no-panic burndown,
TLS mTLS/revocation/CT/browser-store behavior, dependency churn, or mutation
policy weakening.

## Next Safe Action

Start the next lane from a fresh `.uselesskey/goals/active.toml` and linked
plan. The archived PR-lite goal is historical state, not live instructions.
