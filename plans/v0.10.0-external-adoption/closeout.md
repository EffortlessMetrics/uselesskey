+++
id = "USELESSKEY-PLAN-0019"
kind = "plan"
title = "v0.10.0 external adoption closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-17"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0008",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0010",
  "USELESSKEY-SPEC-0011",
  "USELESSKEY-SPEC-0012",
  "USELESSKEY-SPEC-0013",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
+++

# v0.10.0 External Adoption Closeout

## Current State

The v0.10.0 external adoption and installed-user workflow buildout is
implemented. The lane did not prepare or cut a release; it made the eventual
v0.10.0 product target concrete from the outside of the repo.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-v0.10.0-external-adoption.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `cargo xtask external-adoption-smoke --path .` creates clean temporary
  adopter projects, exercises local-path dependency snippets, runs installed
  CLI-shaped commands, generates and verifies scanner-safe, TLS, OIDC/JWKS, and
  webhook bundles, and writes Markdown/JSON receipts.
- `cargo xtask external-adoption-smoke --version <published>` exists as an
  audit/reference mode for published versions and is explicitly not a release
  trigger.
- Installed-user docs separate CLI use, Rust dependency snippets, repo-local
  proof, reviewer evidence, and maintainer evidence so users do not need to
  learn `xtask` before generating a fixture.
- `examples/external/` now contains downstream-shaped webhook, OIDC/JWKS, TLS,
  and Rust test fixture examples that are exercised by external adoption smoke.
- `uselesskey profiles`, `uselesskey profile <name> --explain`,
  `uselesskey bundle --profile <name> --explain`, and
  `uselesskey inspect-bundle --path <dir>` explain generated files,
  scanner-safe posture, runtime material, proof handoffs, and boundaries.
- `docs/explanation/cli-proof-handoff-boundary.md` records the v0.10.0 buildout
  decision: installed CLI proof remains discovery and bundle-local inspection,
  while executable public-claim proof stays in allowlisted repo-local `xtask`
  commands.
- `cargo xtask adoption-regression --external` adds clean-project external
  adoption smoke behind an explicit flag while keeping default
  `cargo xtask adoption-regression` bounded.

## Proof

The closeout proof is:

```bash
cargo xtask external-adoption-smoke --path .
cargo xtask adoption-regression
cargo xtask docs-sync --check
cargo +nightly xtask pr-lite
cargo +nightly xtask pr
git diff --check
```

The default adoption-regression proof remains bounded. Clean-project external
adoption proof is available through:

```bash
cargo xtask adoption-regression --external
```

## Non-Goals Held

This lane did not prepare or cut v0.10.0, bump versions, tag, publish, add a
contract pack, add README badges, switch to shipper, claim provider
compatibility, claim production security properties, start broad refactors, or
introduce dependency churn.

## Release-Prep Handoff

Future v0.10.0 release preparation should start from this implemented surface
instead of reopening the buildout lane. A release lane should verify that the
clean-project examples and installed-user docs still match the version being
released, then run the usual release evidence path from a fresh active goal.

## Follow-Up

If an installed `uselesskey prove` command is ever added, it should be designed
as a separate proof-engine lane. It must stay metadata-only, bundle-local,
non-executing, and must not shell-evaluate claim-ledger command strings or copy
raw generated fixture payloads into reviewer artifacts.
