+++
id = "USELESSKEY-LEARNING-2026-05-usability-polish"
kind = "learning"
title = "Usability needs bounded product paths"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-19"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0018",
  "USELESSKEY-SPEC-0019",
  "USELESSKEY-SPEC-0020",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
linked_plan = "plans/usability-polish/implementation-plan.md"
+++

# Usability Needs Bounded Product Paths

## Trigger

The repo already had release proof, first-run docs, external adoption smoke,
installed bundle audit, and downstream CI polish. The remaining gap was whether
the public surface felt like a small set of product paths instead of a repo
operating system.

## What Changed

The lane tightened three installed/adopter paths:

```text
README/start-here -> install or depend -> generate/audit
facade example -> external clean-project smoke
audit JSON -> strict CI preset -> reviewer checklist
```

The implementation deliberately stayed narrow. It added bounded docs, facade
examples, smoke coverage, and tiny audit policy controls instead of a new
fixture family, release lane, or policy language.

## Evidence

- `README.md` and `docs/how-to/start-here.md` route users by job.
- `USELESSKEY-SPEC-0018` records the install/distribution polish target.
- `USELESSKEY-SPEC-0019` records the facade-first Rust test author target.
- `cargo xtask external-adoption-smoke --path . --library-examples` proves the
  clean-project facade examples.
- `USELESSKEY-SPEC-0020` records the downstream policy preset boundary.
- `uselesskey audit-bundle --ci --expect-profile <profile> --policy strict`
  gives CI a small stable decision point.
- `docs/how-to/use-downstream-policy-pack.md` gives downstream teams preset
  commands and a reviewer checklist.

## Rule to Keep

Keep product paths bounded:

- one job should lead to one command or snippet;
- installed-user evidence should stay metadata-only;
- policy controls should stay presets and stable fields, not a DSL;
- repo-local public-claim proof should stay separate from installed CLI use;
- release prep should be an explicit lane, not an accidental side effect of
  better docs.

## Follow-Up Artifacts

- `plans/usability-polish/closeout.md`
- `.uselesskey/goals/archive/2026-05-usability-polish.toml`
- `docs/how-to/use-downstream-policy-pack.md`
- `docs/specs/USELESSKEY-SPEC-0018-install-distribution-polish.md`
- `docs/specs/USELESSKEY-SPEC-0019-library-facade-polish.md`
- `docs/specs/USELESSKEY-SPEC-0020-downstream-policy-pack.md`
