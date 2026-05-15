+++
id = "USELESSKEY-LEARNING-2026-05-first-run-ux"
kind = "learning"
title = "First-run UX works when proof rails stay behind task routing"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-15"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0008",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0010",
  "USELESSKEY-SPEC-0012",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
]
linked_plan = "plans/first-run-ux/implementation-plan.md"
+++

# First-Run UX Works When Proof Rails Stay Behind Task Routing

## Trigger

v0.9.0 made public claims command-backed and reviewable, but the first user
experience still exposed too much of the repo operating system too early. The
next quality bar was not another proof primitive; it was compressing the path
from intent to a working fixture.

## What Changed

The first-run UX lane moved the proof system behind task-shaped entry points:

```text
pick a job -> copy a command -> generate or verify a fixture
  -> optionally prove the claim -> understand the boundary
```

Users can now start from a task router, contract-pack index, README first-run
path, or CLI profile discovery command before choosing whether to inspect the
claim ledger, specs, receipts, or release evidence.

## Evidence

- `docs/how-to/start-here.md` maps user jobs to copyable commands.
- `docs/contract-packs/README.md` turns contract packs into a visible product
  family.
- `uselesskey profiles` and `uselesskey profile <name> --explain` expose
  profile purpose, generated files, proof commands, and claim boundaries in the
  tool.
- `USELESSKEY-SPEC-0012` prevents a premature CLI proof wrapper from shelling
  out to repo-local `xtask` or arbitrary ledger strings.
- `cargo xtask doctor` reports local proof-environment readiness.
- `cargo xtask user-path-smoke` keeps the first-run bundle and reviewer-proof
  paths executable.

## Rule to Keep

Lead user docs with the job and the first safe command. Put internal nouns such
as claim ledger, contract-pack registry, active goal, and release-evidence lane
behind links unless the user is already in reviewer or maintainer mode.

Proof should be optional from the first-run path, but it must remain one command
away and must state what it does not prove.

## Follow-Up Artifacts

- `plans/first-run-ux/closeout.md`
- `.uselesskey/goals/archive/2026-05-first-run-ux.toml`
- `USELESSKEY-SPEC-0012` for future CLI proof-handoff work
