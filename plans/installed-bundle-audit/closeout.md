+++
id = "USELESSKEY-PLAN-0021"
kind = "plan"
title = "Installed bundle audit closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
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

# Installed Bundle Audit Closeout

## Current State

The installed bundle audit and reviewer handoff lane is implemented. The lane
did not prepare or cut a release; it added a product-facing audit path for
installed CLI-generated bundles.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-installed-bundle-audit.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `uselesskey audit-bundle --path <bundle> --out <dir>` writes
  `bundle-audit.json` and `bundle-audit.md`.
- `uselesskey audit-bundle --path <bundle> --format json` emits a
  machine-readable audit receipt to stdout.
- Audit receipts include bundle profile, manifest version, artifact metadata,
  scanner-safe labels, runtime-material classification, receipt metadata,
  checks, and boundaries.
- Audit receipts are metadata-only and do not copy raw generated fixture
  payloads into the audit packet.
- Audit validates manifest parsing, path containment, generated content,
  required receipts, audit-surface scanner-safe counts, and profile-specific
  generated-file expectations.
- `cargo xtask external-adoption-smoke --path .` now runs installed-style
  `bundle`, `verify-bundle`, `audit-bundle`, and `inspect-bundle` for
  scanner-safe, TLS, OIDC, and webhook bundle profiles.
- User docs now include installed audit reviewer handoff and downstream CI
  recipes.

## Proof

The closeout proof is:

```bash
cargo test -p uselesskey-cli --all-features audit_bundle
cargo test -p xtask external_adoption_smoke
cargo run -p uselesskey-cli -- bundle --profile webhook --out target/audit-test/webhook
cargo run -p uselesskey-cli -- audit-bundle --path target/audit-test/webhook --out target/audit-test/webhook-audit
cargo run -p uselesskey-cli -- audit-bundle --path target/audit-test/webhook --format json
cargo xtask external-adoption-smoke --path . --format json
cargo xtask adoption-regression --external
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
cargo xtask no-blob
git diff --check
```

`cargo xtask pr-lite` was also run and reached the fuzz-build step, but failed
because the active stable toolchain rejected `-Zsanitizer=address`. Rerun with
nightly for the full local PR-lite gate:

```bash
cargo +nightly xtask pr-lite
```

## Boundaries Held

This lane did not prepare or cut v0.10.0, bump versions, tag, publish, add a
contract pack, add README badges, switch to shipper, claim provider
compatibility, claim production security properties, start broad refactors, or
introduce dependency churn.

Installed `audit-bundle` proves local bundle consistency and metadata
classification. It does not prove repo public claims, release readiness,
provider compatibility, production security, scanner evasion, or downstream
verifier correctness.

## Release-Prep Handoff

Future v0.10.0 release preparation should verify that installed audit docs,
external adoption smoke, and downstream CI snippets still match the released
version. Release proof remains in repo-local `xtask` commands.
