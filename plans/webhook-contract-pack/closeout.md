+++
id = "USELESSKEY-PLAN-0010"
kind = "plan"
title = "Webhook contract-pack closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-14"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0011",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
]
+++

# Webhook Contract-Pack Closeout

## Current State

The webhook contract-pack lane is implemented. `uselesskey` now ships a bounded
generic HMAC webhook fixture profile with runnable proof, public-claim
registration, claim-proof support, verification-pack receipts, and minor release
evidence integration.

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-webhook-contract-pack.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `uselesskey bundle --profile webhook` materializes a deterministic webhook
  contract pack under the requested output directory.
- The bundle contains one valid HMAC request and negative fixtures for tampered
  body, wrong secret, stale timestamp, missing signature, and malformed
  signature.
- `cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook`
  verifies the bundle layout, expected rejection classes, evidence file,
  receipts, CLI webhook tests, owner crate tests, and no-blob gate.
- `webhook-contract-pack` is registered in `policy/claim-ledger.toml`,
  `policy/contract-packs.toml`, and `docs/status/PUBLIC_CLAIMS.md`.
- `cargo xtask claim-proof --claim webhook-contract-pack` runs the allowlisted
  webhook proof handler without shell-evaluating ledger command strings.
- `cargo xtask verification-pack --out <dir> --claim webhook-contract-pack`
  writes metadata-only webhook review receipts.
- Minor release evidence includes the webhook proof; patch release evidence
  remains scoped to the cheaper patch lane.
- User docs explain what the webhook pack proves and what remains outside the
  claim boundary.

## Proof

The closeout proof is:

```bash
cargo xtask spec-check --strict
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo xtask claim-proof --claim webhook-contract-pack
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

## Non-Goals Held

This lane did not add a provider-specific webhook compatibility matrix,
production secret-management claims, replay-policy claims, TLS expansion,
shipper migration work, historical no-panic baseline work, dependency churn, or
new README badges.

## Next Safe Action

Start the next product or reliability lane from a fresh
`.uselesskey/goals/active.toml` and linked plan. The archived webhook goal is
historical state, not live instructions.
