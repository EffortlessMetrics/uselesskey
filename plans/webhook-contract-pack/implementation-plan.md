+++
id = "USELESSKEY-PLAN-0009"
kind = "plan"
title = "Webhook contract pack"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-14"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0005",
]
linked_adrs = []
+++

# Webhook Contract Pack

## Objective

Ship a bounded webhook contract pack that lets users generate deterministic
HMAC-SHA256 webhook verification fixtures, run positive and negative verifier
checks locally, produce command-backed receipts, and share metadata-only proof
with reviewers.

This lane spends the completed source-of-truth, claim-backed verification,
PR-lite, and no-panic rails on user-visible product value.

## Scope

This lane covers:

- a product spec for the webhook contract pack and its claim boundary;
- `uselesskey bundle --profile webhook`;
- deterministic request fixtures for one valid case and bounded negative cases;
- `cargo xtask bundle-proof --profile webhook`;
- claim-ledger and contract-pack registry entries;
- a whitelisted `claim-proof` handler for `webhook-contract-pack`;
- task-first user docs for webhook signature validation;
- minor release-evidence integration;
- verification-pack documentation and closeout.

## Claim Boundary

The webhook contract pack proves deterministic HMAC webhook verifier behavior
for fixture requests.

It does not prove production webhook provider compatibility, secret rotation,
delivery retries, timestamp policy suitability, replay protection completeness,
transport security, or production secret management.

## Target Fixture Shape

The generated pack should use a small, stable shape:

```text
manifest.json
requests/valid.json
requests/negative-tampered-body.json
requests/negative-wrong-secret.json
requests/negative-stale-timestamp.json
requests/negative-missing-signature.json
requests/negative-malformed-signature.json
receipts/materialization.json
receipts/audit-surface.json
evidence/webhook-profile.md
```

Each request fixture should record:

```text
method
path
timestamp
body
headers
expected_result
rejection_class
```

Expected rejection classes should be stable identifiers:

```text
valid
tampered_body
wrong_secret
stale_timestamp
missing_signature
malformed_signature
```

## Non-Goals

Do not mix these into this lane:

- provider-specific webhook compatibility matrices;
- production secret management;
- replay-policy product claims;
- transport-security claims;
- TLS, mTLS, revocation, CT, or browser trust-store behavior;
- shipper migration work;
- no-panic historical baseline burndown;
- README badge additions;
- dependency churn.

## PR Sequence

1. Open this active lane and implementation plan.
2. Add `docs/specs/USELESSKEY-SPEC-0011-webhook-contract-pack.md`.
3. Implement `uselesskey bundle --profile webhook`.
4. Add `cargo xtask bundle-proof --profile webhook`.
5. Register `webhook-contract-pack` in `policy/claim-ledger.toml`,
   `policy/contract-packs.toml`, and `docs/status/PUBLIC_CLAIMS.md`.
6. Add a whitelisted `cargo xtask claim-proof --claim webhook-contract-pack`
   handler.
7. Add task-first webhook signature validation docs.
8. Wire webhook proof into minor release evidence while keeping patch evidence
   cheap unless webhook surfaces are touched.
9. Polish verification-pack docs for the webhook user path.
10. Close out the lane with a learning record and archived active goal.

## Proof Commands

Lane-opening PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Product implementation PRs:

```bash
cargo test -p uselesskey-webhook --all-features
cargo test -p uselesskey-cli --all-features webhook
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask claim-proof --claim webhook-contract-pack
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

Release-evidence PR:

```bash
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
cargo xtask spec-check --strict
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

## Rollback

Each PR should be independently revertible. If the implementation proves too
broad, revert the product-code PRs and leave the lane plan active for a smaller
spec revision. Do not leave claim-ledger or contract-pack registry entries for
unimplemented behavior.

## Stop Conditions

Pause and split work if the lane requires provider-specific compatibility
claims, production secret management semantics, dependency additions, new README
badges, historical no-panic baseline work, release execution, shipper work, or
TLS expansion.
