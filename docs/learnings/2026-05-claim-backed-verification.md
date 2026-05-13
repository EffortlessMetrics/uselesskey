+++
id = "USELESSKEY-LEARNING-2026-05-claim-backed-verification"
kind = "learning"
title = "Public claims are useful when users can run the proof"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-13"
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
linked_plan = "plans/claim-backed-verification/implementation-plan.md"
+++

# Public Claims Are Useful When Users Can Run the Proof

## Trigger

The spec-system lane made public claims traceable, but traceability alone still
required users to assemble commands and receipts by hand. The badge stack,
claim ledger, and release-evidence lanes needed a user-facing proof path.

## What Changed

`uselesskey` now treats public claims as runnable proof surfaces:

```text
claim ledger -> claim report -> claim proof -> verification pack
```

Users can generate a claim index, run allowlisted proof handlers for supported
claims, and hand a metadata-only verification pack to a security, platform, or
release reviewer.

## Evidence

- `cargo xtask claim-report` writes `target/claim-report/public-claims.md` and
  `.json`.
- `cargo xtask claim-report --check-public-claims` keeps
  `docs/status/PUBLIC_CLAIMS.md` aligned with `policy/claim-ledger.toml`.
- `cargo xtask contract-packs --check` validates stable contract-pack entries.
- `cargo xtask claim-proof --all-stable` writes per-claim receipts without
  shell-evaluating ledger command strings.
- `cargo xtask verification-pack --out target/uselesskey-verification` collects
  metadata-only review receipts.
- Release-evidence dry runs include claim-report, contract-pack, and
  verification-pack receipts.

## Rule to Keep

Do not make users infer proof from badges. A public claim should point to a
claim-report entry, a runnable proof command or explicit advisory boundary, and
a receipt path that can be attached to review.

Verification packs must remain metadata-only. Generated fixture payloads belong
under `target/` proof directories and should not be copied into reviewer packs.

## Follow-up Artifacts

Future fixture profiles should add or update:

- `policy/claim-ledger.toml`;
- `policy/contract-packs.toml` when the profile is a contract pack;
- task-first how-to docs;
- claim-proof handler mappings only when the proof can be allowlisted safely;
- release-evidence mapping when the claim becomes shipped public truth.
