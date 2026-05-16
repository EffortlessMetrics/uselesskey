+++
id = "USELESSKEY-PLAN-0015"
kind = "plan"
title = "Adoption confidence closeout"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-16"
milestone = "v0.9.1"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0004",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0008",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0010",
  "USELESSKEY-SPEC-0011",
  "USELESSKEY-SPEC-0012",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
+++

# Adoption Confidence Closeout

## Current State

The adoption correctness and fixture confidence pass is implemented. The
first-run UX lane made the product easier to approach; this pass made the easy
paths more trustworthy under fixture, adapter, and proof checks.

The archived goal manifest is
`.uselesskey/goals/archive/2026-05-adoption-confidence.toml`. The root
`.uselesskey/goals/active.toml` records the lane as archived until the next
lane is selected.

## Implemented Surface

- Runtime public asymmetric JWK and JWKS bundle metadata now classifies public
  material as scanner-safe while keeping secret-bearing HMAC, token, and
  private key outputs outside that claim.
- `cargo xtask adoption-regression` writes Markdown and JSON receipts for the
  copied user-path contract.
- Webhook, SSH, PKCS#11 mock, test-server, axum, rustls, JWK, token, RSA,
  ECDSA, Ed25519, HMAC, entropy, PGP, jsonwebtoken, and X.509 confidence
  coverage now exercises deterministic identity, negative fixtures, adapter
  behavior, public JWK/JWKS shape, debug/redaction-sensitive surfaces, and
  clone/cache invariants where applicable.
- X.509 self-signed generation no longer leaves new no-panic debt from the SRP
  split, and the no-panic baseline was refreshed without absorbing new debt.
- Stale or out-of-lane generated SRP refactor drafts were closed instead of
  mixing broad refactors into a fixture-confidence pass.

## Proof

The closeout proof is:

```bash
cargo xtask adoption-regression
cargo xtask adoption-regression --format json
cargo xtask check-no-panic-family
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo xtask docs-sync --check
cargo +nightly xtask pr-lite
cargo xtask pr
git diff --check
```

## Non-Goals Held

This pass did not add a new contract pack, README badge, provider compatibility
claim, production security claim, shipper migration, broad SRP refactor,
historical no-panic burndown, or release machinery change.

## Parked Work

The generated badge refresh PR remains parked as front-panel maintenance, not
adoption-confidence work.

Future dependency updates should remain separate dependency-maintenance work
unless a security or release-blocking reason requires them.

## Patch Release Decision

The runtime scanner-safe metadata fix is user-visible and already landed on
`main` after v0.9.0. A narrow v0.9.1 patch is justified if the maintainer wants
that fix and the confidence receipts available from a published version before
the next product lane.

Keep v0.9.1 scope narrow:

- runtime public JWK/JWKS scanner-safe metadata correction;
- adoption-regression receipt command;
- fixture-confidence tests and no-panic restoration;
- no new product claims, profiles, badges, or contract packs.
