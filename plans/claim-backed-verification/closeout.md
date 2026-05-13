+++
id = "USELESSKEY-PLAN-0004"
kind = "plan"
title = "Claim-backed verification UX closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0004",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0008",
  "USELESSKEY-SPEC-0009",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
+++

# Claim-Backed Verification UX Closeout

## Current State

The claim-backed verification UX lane is implemented. `uselesskey` now exposes
public claims as a discoverable, runnable, and reviewable proof path:

```text
README badge -> verification docs -> PUBLIC_CLAIMS
  -> claim-report -> claim-proof -> verification-pack -> release evidence
```

The active goal manifest for this lane is archived at
`.uselesskey/goals/archive/2026-05-claim-backed-verification.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until a new lane is
selected.

## Implemented Surface

- `cargo xtask claim-report` emits Markdown and JSON receipts from
  `policy/claim-ledger.toml`.
- `cargo xtask claim-report --check-public-claims` checks
  `docs/status/PUBLIC_CLAIMS.md` against the ledger.
- `cargo xtask contract-packs --check` validates stable contract-pack registry
  entries against claims, specs, proof commands, and how-to docs.
- `cargo xtask claim-proof` runs allowlisted proof handlers for selected stable
  claims and writes per-claim receipts under `target/claim-proof/`.
- `cargo xtask verification-pack --out <dir>` builds metadata-only reviewer
  bundles with claim reports, contract-pack reports, badge endpoint JSON, and
  selected claim-proof receipts.
- Release evidence includes claim-report receipts, contract-pack registry
  receipts, and verification-pack receipts for the appropriate lanes.
- README, verification docs, public claims, and how-to guides now direct users
  from public trust markers to runnable proof commands and explicit boundaries.

## Proof

The closeout proof is:

```bash
cargo xtask spec-check --strict
cargo xtask claim-report
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo xtask claim-proof --all-stable
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Release-evidence dry-run proof from the lane:

```bash
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
```

## Non-Goals Held

This lane did not add new fixture profiles, TLS mTLS/revocation/CT/browser-store
behavior, shipper migration work, no-panic cleanup, dependency churn, new
README badges, automatic direct-to-main badge writes, or generated fixture
payloads in verification packs.

## Next Safe Action

Start the next lane from a fresh `.uselesskey/goals/active.toml` and linked
plan. The archived claim-backed verification goal is historical state, not live
instructions.
