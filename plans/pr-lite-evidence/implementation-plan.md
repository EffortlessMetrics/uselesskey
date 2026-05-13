+++
id = "USELESSKEY-PLAN-0005"
kind = "plan"
title = "PR-lite evidence ergonomics"
status = "accepted"
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

# PR-Lite Evidence Ergonomics

## Objective

Make local PR evidence approximate hosted CI closely enough to reduce wasted CI
cycles, and make heavy evidence routing explain itself.

## Scope

This lane covers developer and agent evidence ergonomics:

- `cargo xtask pr-lite` as local bounded PR evidence;
- Markdown and JSON PR-lite receipts under `target/pr-lite/`;
- mutation routing receipts explaining why targeted mutation runs or skips;
- safe diff-scoped mutation only when supported, with fallback receipts;
- agent and local-validation docs for honest evidence reporting.

## Non-Goals

Do not mix these into this lane:

- new product claims;
- new fixture profiles;
- release execution;
- shipper re-migration;
- no-panic burndown;
- mutation policy weakening;
- TLS mTLS, revocation, CT, or browser trust-store behavior;
- dependency churn;
- new README badges.

## PR Sequence

1. Open this active lane and implementation plan.
2. Add `USELESSKEY-SPEC-0010` for PR-lite evidence and heavy-routing receipts.
3. Add `cargo xtask pr-lite` with Markdown and JSON receipts.
4. Add mutation routing explanation receipts.
5. Add diff-scoped mutation where safe, with fallback.
6. Add local validation and evidence routing docs.
7. Close out the lane with a learning record and archived goal manifest.

## Proof Commands

Lane-opening PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Final lane proof:

```bash
cargo test -p xtask pr_lite
cargo xtask pr-lite
cargo xtask pr-lite --format json
cargo xtask mutants-pr --changed --explain
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

## Stop Conditions

Pause and split work if a PR would require product behavior, release execution,
new fixture profiles, TLS expansion, dependency churn, or weakening mutation
requirements.
