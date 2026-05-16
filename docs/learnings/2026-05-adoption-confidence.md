+++
id = "USELESSKEY-LEARNING-2026-05-adoption-confidence"
kind = "learning"
title = "Easy fixture paths need confidence receipts"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-05-16"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
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
  "USELESSKEY-ADR-0004",
]
linked_plan = "plans/adoption-confidence/closeout.md"
+++

# Easy Fixture Paths Need Confidence Receipts

## Trigger

v0.9.0 and the first-run UX lane made `uselesskey` approachable: users could
pick a job, copy a command, generate fixtures, and find proof boundaries. That
made correctness bugs in the copied path more important. A scanner-safe metadata
bug in runtime public JWK output showed that the next quality bar was
adoption-grade confidence, not more UX scaffolding.

## What Changed

The adoption-confidence pass hardened the copied paths:

```text
start-here command -> generated fixture -> manifest/audit metadata
  -> scanner-safe classification -> negative fixture behavior
  -> debug/redaction invariant -> adoption-regression receipt
```

The lane fixed runtime public JWK/JWKS scanner-safe metadata, added the
adoption-regression receipt, restored no-panic new-debt posture after the X.509
SRP split, and merged fixture-confidence coverage across the main crate,
contract-pack, and adapter families.

## Evidence

- Runtime public asymmetric JWK/JWKS metadata is covered end to end.
- `cargo xtask adoption-regression` exercises user-path smoke, runtime
  scanner-safe matrix checks, webhook profile tests, TLS/OIDC bundle proofs,
  and `no-blob`.
- Token, RSA, ECDSA, Ed25519, HMAC, entropy, JWK, PGP, X.509, PKCS#11 mock,
  test-server, axum, rustls, SSH, webhook, and jsonwebtoken coverage now pins
  fixture identity, negative behavior, adapter validation, redaction-sensitive
  output, or public JWK/JWKS shape where relevant.
- `cargo xtask check-no-panic-family` returns 0 new debt, 0 stale baseline
  entries, and 0 expired allowlist entries.
- Stale broad SRP refactor drafts were closed rather than mixed into the
  confidence pass.

## Rule to Keep

Do not treat coverage volume as adoption confidence. Prefer tests and receipts
that protect a user-visible fixture promise: scanner-safe labels, deterministic
identity, negative fixture semantics, adapter round-trips, redaction-sensitive
debug output, and generated-bundle metadata.

When a confidence pass reveals broad refactor drafts, close or park them unless
they are required to prove the copied user path.

## Follow-Up Artifacts

- `plans/adoption-confidence/closeout.md`
- `.uselesskey/goals/archive/2026-05-adoption-confidence.toml`
- v0.9.1 patch-release decision for the runtime scanner-safe metadata fix
