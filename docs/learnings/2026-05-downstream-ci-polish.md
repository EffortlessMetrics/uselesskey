+++
id = "USELESSKEY-LEARNING-2026-05-downstream-ci-polish"
kind = "learning"
title = "Installed audit needs stable CI behavior"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-18"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0012",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
]
linked_plan = "plans/downstream-ci-polish/implementation-plan.md"
+++

# Installed Audit Needs Stable CI Behavior

## Trigger

The installed bundle audit lane gave users metadata-only audit receipts. The
next downstream question was whether those receipts were stable enough for CI
jobs, automation policies, and day-to-day terminal use.

## What Changed

The installed audit loop now has three surfaces with distinct jobs:

```text
inspect-bundle -> quick human read
audit-bundle --ci -> stable JSON decision point
audit-bundle --summary -> compact human CI log
```

The lane also added downstream CI recipes, an external clean-project CI example,
golden audit receipt coverage, installed CLI doctor checks, and tested
`external-adoption-smoke --ci-recipes`.

## Evidence

- `docs/schemas/bundle-audit.schema.json` and
  `docs/reference/bundle-audit-json.md` define the audit JSON contract.
- `uselesskey audit-bundle --ci` exits non-zero on stable failure classes.
- `uselesskey audit-bundle --summary` reports pass/profile/artifact counts,
  scanner-safe counts, runtime-material counts, receipt presence, and the local
  consistency boundary.
- `cargo xtask external-adoption-smoke --path . --ci-recipes --format json`
  proves documented downstream CI recipes.
- `cargo xtask adoption-regression --external` includes the external installed
  path.
- Golden snapshots under `crates/uselesskey-cli/tests/snapshots/` protect audit
  JSON/Markdown schema shape and boundary language.

## Rule to Keep

Keep installed-user CI behavior stable and boring:

- JSON is for machines;
- summary and inspect output are for humans;
- audit receipts are metadata-only;
- stable failure classes are the downstream CI contract;
- repo-local public-claim proof remains separate from installed audit.

## Follow-Up Artifacts

- `plans/downstream-ci-polish/closeout.md`
- `.uselesskey/goals/archive/2026-05-downstream-ci-polish.toml`
- `docs/reference/bundle-inspect-vs-audit.md`
- `docs/how-to/use-uselesskey-in-github-actions.md`
- `examples/external/downstream-ci-bundle-audit/`
