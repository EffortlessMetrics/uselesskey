+++
id = "USELESSKEY-PLAN-0017"
kind = "plan"
title = "v0.9.1 release closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-17"
milestone = "v0.9.1"
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
]
linked_adrs = [
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0004",
]
+++

# v0.9.1 Release Closeout

## Current State

v0.9.1 is published and audited.

The release shipped the narrow adoption-confidence patch:

- runtime public asymmetric JWK/JWKS scanner-safe metadata correction;
- `cargo xtask adoption-regression` receipt proof;
- fixture-confidence coverage for copied user paths;
- no-panic-family Stage A.5 new-debt restoration;
- current copyable how-to snippets;
- no new product claims, profiles, contract packs, or badges.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-v0.9.1-release.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Release Identity

- Tag: `v0.9.1`
- Tag SHA: `fc69fb4acc6d585505b11b50ec1ca76cf8d49f98`
- GitHub release:
  <https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.9.1>
- Release workflow:
  <https://github.com/EffortlessMetrics/uselesskey/actions/runs/25989100361>
- Audit record: `docs/release/post-release-audit-v0.9.1.md`

## Proof

The release lane proof included:

```bash
cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary
cargo xtask adoption-regression
cargo xtask adoption-regression --format json
cargo xtask claim-proof --all-stable
cargo xtask user-path-smoke
cargo xtask check-no-panic-family
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo +nightly xtask pr-lite
cargo xtask pr
cargo xtask publish-preflight
cargo xtask publish-check
cargo xtask no-blob
cargo xtask badges --check
cargo xtask docs-sync --check
cargo xtask cratesio-smoke --version 0.9.1
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask public-surface
git diff --check
```

## Audit Finding

No release defect was found.

The tag-triggered Release workflow succeeded through preflight, publish, and
GitHub release creation. This confirmed the release-authority cleanup from the
v0.9.0 audit: v0.9.1 used one release creation authority.

## Non-Goals Held

This lane did not add a new contract pack, add README badges, claim provider
compatibility, claim production security properties, switch to shipper, start
historical no-panic baseline cleanup, or do broad dependency churn.

## Next Safe Action

Start the next product or reliability lane from a fresh
`.uselesskey/goals/active.toml` and linked plan. The archived v0.9.1 release
goal is historical state, not live instruction.
