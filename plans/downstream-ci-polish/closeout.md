+++
id = "USELESSKEY-PLAN-0023"
kind = "plan"
title = "Downstream CI polish closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
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
+++

# Downstream CI Polish Closeout

## Current State

The downstream CI and installed-user polish lane is implemented and archived.
The lane did not prepare or cut a release; it made the installed bundle audit
loop more stable, scriptable, and pleasant for downstream CI.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-downstream-ci-polish.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `docs/schemas/bundle-audit.schema.json` and
  `docs/reference/bundle-audit-json.md` document the stable audit JSON contract.
- `uselesskey audit-bundle --ci` emits machine-readable JSON and exits non-zero
  on stable audit failure classes.
- Downstream CI and GitHub Actions docs show generate, verify, audit, and
  metadata-only artifact handoff.
- `cargo xtask external-adoption-smoke --path . --ci-recipes` exercises
  documented CI-style bundle audit recipes.
- Audit failure diagnostics now keep stable machine-readable classes while
  giving humans actionable causes and fixes.
- `uselesskey doctor` reports installed-user environment checks without
  reaching into repo-local proof tools.
- `inspect-bundle` and `audit-bundle` wording now separates quick terminal
  summaries from durable reviewer/CI receipts.
- `examples/external/downstream-ci-bundle-audit/` models the downstream CI loop
  and is part of external-adoption smoke.
- Golden snapshots protect audit JSON/Markdown shape, boundary language, and
  metadata-only posture.
- `uselesskey audit-bundle --summary` gives compact human output for terminal
  and CI logs while keeping `--ci` as the machine-readable path.

## Proof

The closeout proof is:

```bash
cargo xtask external-adoption-smoke --path . --format json
cargo xtask adoption-regression --external
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo xtask check-no-panic-family
cargo xtask docs-sync --check
cargo xtask typos
cargo +nightly xtask pr-lite
cargo xtask pr
git diff --check
```

Earlier PR slices also ran the focused checks for their surfaces, including:

```bash
cargo test -p uselesskey-cli --all-features audit_bundle
cargo test -p uselesskey-cli --all-features doctor
cargo test -p xtask external_adoption_smoke
cargo xtask external-adoption-smoke --path . --ci-recipes --format json
cargo xtask no-blob
cargo xtask badges --check
```

## Boundaries Held

This lane did not prepare or cut v0.10.0, bump versions, tag, publish, add a
contract pack, add README badges, switch to shipper, claim provider
compatibility, claim production security properties, claim scanner evasion,
start broad refactors, or introduce dependency churn.

Installed `audit-bundle` remains local bundle consistency evidence. It does not
prove repo public claims, release readiness, provider compatibility, production
security, scanner evasion, or downstream verifier correctness.

## Release-Prep Handoff

Future v0.10.0 release preparation should verify the installed CLI help,
downstream CI docs, external-adoption smoke receipts, audit JSON schema, and
compact summary output against the release version. Release proof remains
repo-local.
