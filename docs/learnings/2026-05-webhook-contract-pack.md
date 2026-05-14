+++
id = "USELESSKEY-LEARNING-2026-05-webhook-contract-pack"
kind = "learning"
title = "Contract packs become real when a new user workflow uses every proof rail"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-14"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0011",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
]
linked_plan = "plans/webhook-contract-pack/implementation-plan.md"
+++

# Contract Packs Become Real When a New User Workflow Uses Every Proof Rail

## Trigger

The spec-system, claim-backed verification, PR-lite, and no-panic lanes built
the operating model. The webhook lane tested whether that model could carry new
user-visible product value without becoming paperwork.

## What Changed

The webhook contract pack turned the infrastructure into an applied verifier
workflow:

```text
spec -> bundle profile -> bundle proof -> claim ledger -> contract-pack registry
  -> claim-proof -> verification-pack -> release evidence -> task-first docs
```

Users can now generate deterministic HMAC webhook request fixtures, verify valid
and negative cases, and attach metadata-only receipts to a security or platform
review.

## Evidence

- `uselesskey bundle --profile webhook` writes the deterministic pack.
- `cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook`
  writes release-evidence receipts.
- `cargo xtask claim-proof --claim webhook-contract-pack` runs the allowlisted
  proof handler.
- `cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack`
  writes a shareable metadata-only reviewer bundle.
- Minor release evidence includes webhook proof while patch evidence stays
  cheap.

## Rule to Keep

New contract packs should start with a spec and boundary, then land only when
the pack can move through claim ledger, contract-pack registry, proof command,
claim-proof handler, verification-pack receipt, release evidence, and a
task-first how-to.

Do not turn a useful fixture profile into a broad compatibility claim. The
webhook pack proves documented generic HMAC verifier fixtures, not provider
compatibility, production secret management, replay protection completeness,
transport security, or downstream verifier correctness.

## Follow-up Artifacts

Future contract-pack work should update:

- `docs/specs/USELESSKEY-SPEC-0003-contract-pack-profile.md` if the lifecycle
  changes;
- `policy/claim-ledger.toml` and `policy/contract-packs.toml` for public claims;
- claim-proof and verification-pack handlers for runnable receipts;
- release-evidence wiring when the claim becomes a minor-release promise.
