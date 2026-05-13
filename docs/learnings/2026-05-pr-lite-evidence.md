+++
id = "USELESSKEY-LEARNING-2026-05-pr-lite-evidence"
kind = "learning"
title = "Local evidence is useful when its boundary is explicit"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-13"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0010",
]
linked_adrs = []
linked_plan = "plans/pr-lite-evidence/implementation-plan.md"
+++

# Local Evidence Is Useful When Its Boundary Is Explicit

## Trigger

The claim-backed verification lane made public claims auditable, but normal PR
work still had a different cost problem: local checks could under-approximate
hosted CI, and heavy evidence such as targeted mutation could be hard to explain
while it was running.

## What Changed

`uselesskey` now separates local PR evidence from hosted and release proof:

```text
pr-lite -> mutation routing receipt -> hosted CI -> release evidence
```

`cargo xtask pr-lite` gives contributors and agents a bounded local check with
receipts, while `cargo xtask mutants-pr --changed --explain` records why
targeted mutation is required, skipped, diff-scoped, or crate-scoped.

## Evidence

- `cargo xtask pr-lite` writes `target/pr-lite/pr-lite.md` and `.json`.
- `cargo xtask mutants-pr --changed --explain` writes
  `target/xtask/mutation-routing/latest.md` and `.json`.
- Diff-scoped mutation is attempted only for clean Rust owner-path mappings.
- Full-owner mutation stays crate-scoped.
- Local-validation docs define the difference between PR-lite, full PR, hosted
  CI, mutation evidence, claim proof, and release evidence.

## Rule to Keep

Do not report `pr-lite` as "all gates passed." Use precise language:

```text
Local PR-lite passed; hosted CI and full PR evidence remain separate.
```

Use "all required gates passed" only after the relevant local command and hosted
required checks have completed.

## Follow-up Artifacts

Future evidence-routing changes should update:

- `docs/specs/USELESSKEY-SPEC-0010-pr-lite-evidence.md` when behavior changes;
- `docs/handoffs/local-validation.md` when reporting rules change;
- `.uselesskey/goals/active.toml` and the linked implementation plan for active
  lane state.
