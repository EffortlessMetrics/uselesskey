+++
id = "USELESSKEY-LEARNING-2026-05-installed-bundle-audit"
kind = "learning"
title = "Installed bundles need local audit receipts"
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
linked_plan = "plans/installed-bundle-audit/implementation-plan.md"
+++

# Installed Bundles Need Local Audit Receipts

## Trigger

The external-adoption lane proved that users can generate and verify bundles
from clean projects. The next reviewer question was not whether generation
works, but how an installed user can explain one generated bundle without
cloning the repo or running public-claim proof.

## What Changed

The installed CLI now has a metadata-only audit handoff:

```text
bundle -> verify-bundle -> audit-bundle -> inspect-bundle
```

`audit-bundle` writes JSON and Markdown receipts that summarize manifest
version, artifacts, scanner-safe labels, runtime-material classification,
receipts, checks, and boundaries. External adoption smoke exercises the audit
step for installed-style scanner-safe, TLS, OIDC, and webhook bundles.

## Evidence

- `uselesskey audit-bundle --path <bundle> --out <dir>` writes
  `bundle-audit.json` and `bundle-audit.md`.
- `uselesskey audit-bundle --path <bundle> --format json` emits machine-readable
  metadata for downstream CI.
- `cargo xtask external-adoption-smoke --path . --format json` records
  `cli-audit-*` steps and audit output directories for scanner-safe, TLS, OIDC,
  and webhook bundles.
- `cargo xtask adoption-regression --external` passes with the installed audit
  step included.

## Rule to Keep

Keep installed audit and repo proof separate:

- installed `audit-bundle` proves local bundle consistency and metadata
  classification;
- repo-local `claim-proof` and `verification-pack` prove public claims;
- release evidence proves release readiness.

Do not let installed audit shell out to `xtask`, execute claim-ledger command
strings, or copy generated fixture payloads into reviewer packets.

## Follow-Up Artifacts

- `plans/installed-bundle-audit/closeout.md`
- `.uselesskey/goals/archive/2026-05-installed-bundle-audit.toml`
- `USELESSKEY-SPEC-0014` for installed bundle audit
- `docs/how-to/share-installed-bundle-audit.md`
- `docs/how-to/use-uselesskey-in-downstream-ci.md`
