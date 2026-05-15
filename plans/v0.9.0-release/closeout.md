+++
id = "USELESSKEY-PLAN-0012"
kind = "plan"
title = "v0.9.0 release closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-14"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0004",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0007",
  "USELESSKEY-SPEC-0008",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0010",
  "USELESSKEY-SPEC-0011",
]
linked_adrs = [
  "USELESSKEY-ADR-0002",
]
+++

# v0.9.0 Release Closeout

## Current State

v0.9.0 is published and audited.

The release shipped the command-backed fixture-platform surface:

- source-of-truth specs and ledgers;
- generated badge endpoints;
- `claim-report`, `claim-proof`, and `verification-pack`;
- PR-lite evidence and heavy-routing receipts;
- no-panic-family Stage A.5 new-debt posture;
- TLS, OIDC/JWKS, and webhook contract-pack proof;
- post-release crates.io, docs.rs, claim-proof, verification-pack, and
  bundle-proof audit.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-v0.9.0-release.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Release Identity

- Tag: `v0.9.0`
- Tag SHA: `b03772d01e3d194a638b5b6a606f551c436adc43`
- GitHub release:
  <https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.9.0>
- Audit record: `docs/release/post-release-audit-v0.9.0.md`

## Proof

The release lane proof included:

```bash
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask publish-preflight
cargo xtask publish-check
cargo xtask no-blob
cargo xtask check-no-panic-family
cargo xtask badges --check
cargo xtask docs-sync --check
cargo xtask spec-check --strict
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo xtask pr
cargo xtask publish
cargo xtask cratesio-smoke --version 0.9.0
cargo xtask claim-proof --all-stable
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask public-surface
git diff --check
```

## Audit Finding

The tag-triggered Release workflow succeeded through preflight and publish, then
failed only when creating the GitHub release because the release already existed
from the manual curated-notes step.

This did not affect published crate state, docs.rs state, or post-release proof.
Future release automation should either make release creation idempotent or keep
GitHub release creation as a single explicit operator action.

## Non-Goals Held

This lane did not add another contract pack, switch to shipper, add README
badges, expand TLS into production PKI semantics, start historical no-panic
baseline cleanup, or do dependency churn.

## Next Safe Action

Start the next product or reliability lane from a fresh
`.uselesskey/goals/active.toml` and linked plan. The archived v0.9.0 release
goal is historical state, not live instruction.
