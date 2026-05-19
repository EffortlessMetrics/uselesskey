+++
id = "USELESSKEY-PLAN-0026"
kind = "plan"
title = "Usability polish closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-19"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0012",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0017",
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
+++

# Usability Polish Closeout

## Current State

The usability polish lane is implemented and archived. The lane did not prepare
or cut v0.10.0; it made the current installed and facade-facing product path
clearer for downstream users.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-usability-polish.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `USELESSKEY-SPEC-0018` defines install and distribution polish boundaries for
  the v0.10.0 product-quality target without starting release prep.
- The README front door now routes users by job: facade dependency, installed
  CLI bundles, contract-pack profiles, downstream CI audit, reviewer handoff,
  and repo-local public-claim proof.
- Installed CLI help and `uselesskey doctor` were audited for user-facing
  self-check behavior without routing installed users through `xtask`.
- `USELESSKEY-SPEC-0019` defines the library facade polish target for clean
  Rust test projects and feature-flag discoverability.
- Facade-first external examples show downstream-shaped Rust test usage without
  requiring users to discover leaf crate internals before first value.
- `cargo xtask external-adoption-smoke --path . --library-examples` proves the
  facade examples in bounded clean-project mode.
- `USELESSKEY-SPEC-0020` defines downstream policy presets and explicitly keeps
  policy work out of broad DSL territory.
- `uselesskey audit-bundle --ci --expect-profile <profile> --policy strict`
  gives downstream CI a tiny profile expectation and strict preset.
- `docs/how-to/use-downstream-policy-pack.md` documents `default`, `strict`,
  and `reviewer` presets plus a reviewer checklist and metadata-only handoff.

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

Earlier PR slices also ran focused checks for their surfaces, including:

```bash
cargo run -p uselesskey-cli -- --help
cargo run -p uselesskey-cli -- doctor --format json
cargo test -p uselesskey-cli --all-features audit_bundle
cargo test -p uselesskey-cli --all-features doctor
cargo test -p xtask external_adoption_smoke
cargo xtask external-adoption-smoke --path . --library-examples
cargo xtask external-adoption-smoke --path . --ci-recipes
cargo xtask mutants-pr --changed
cargo xtask badges --check
```

## Boundaries Held

This lane did not prepare or cut v0.10.0, bump versions, tag, publish, add a
contract pack, add README badges, switch to shipper, claim provider
compatibility, claim production security properties, add a broad policy DSL,
start broad refactors, or introduce dependency churn.

Installed CLI commands still do not execute `xtask`, release evidence, or
claim-ledger command strings.

## Release-Prep Handoff

Future v0.10.0 release preparation should verify the README front door, install
commands, facade examples, external smoke receipts, downstream policy docs, and
audit policy controls against the release version. Release proof remains
repo-local.

## Follow-Up

The next product lane should start from the installed and facade-facing paths
now in place. Good candidates are release preparation for v0.10.0, broader
distribution/install polish, or a new contract-pack lane, but none of those are
part of this closeout.
