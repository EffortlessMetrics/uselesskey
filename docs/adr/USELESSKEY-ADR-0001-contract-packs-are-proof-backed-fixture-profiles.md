+++
id = "USELESSKEY-ADR-0001"
kind = "adr"
title = "Contract packs are proof-backed fixture profiles"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = ["USELESSKEY-SPEC-0003"]
+++

# USELESSKEY-ADR-0001: Contract Packs Are Proof-Backed Fixture Profiles

## Decision

`uselesskey` contract packs are proof-backed fixture profiles.

A stable contract pack must include a profile name, fixture list, positive
cases, negative cases, receipts, proof command, task-first how-to, release
evidence mapping, scanner-safety rule, and explicit claim boundary.

Generated files alone are not a contract pack.

## Context

The TLS v0.8.0 lane showed the useful pattern:

```text
design -> implementation -> proof -> how-to -> release evidence
```

That pattern is valuable because `uselesskey` operates in a sensitive fixture
space. Users need generated material that looks realistic enough to exercise
parsers and validators, but the repo must not imply production security,
certificate authority behavior, scanner evasion, or downstream verifier
correctness.

The same shape applies to OIDC/JWKS and future packs such as webhook,
WebAuthn, PKCS#11, Vault/Kubernetes exports, or TLS adapter-helper packs. Each
pack needs a repeatable proof model rather than one-off README language.

## Consequences

Stable packs become auditable. A user can find the profile, generated fixtures,
proof command, receipt, how-to, and out-of-scope boundary.

Release evidence becomes composable. Minor releases can carry full pack proofs,
while patch releases can run narrower evidence unless pack behavior or claim
text changes.

The README can stay small. Pack details belong in specs, how-to docs, claim
ledgers, and release receipts rather than the masthead.

New packs have a higher entry bar. They need docs and proof before they become
stable public claims.

## Alternatives Considered

Treat bundle profiles as generated folders only.

Rejected because generated files do not explain what downstream behavior is
promised, which negative paths are covered, or what is outside the boundary.

Document each pack only in a how-to guide.

Rejected because how-to docs teach workflows but should not be the only source
of release evidence, claim boundaries, and proof command ownership.

Put all pack details in the README.

Rejected because the README should be first-hour product truth, not a proof
matrix.

Require full pack proofs on every PR.

Rejected because the release lane should carry full shipped-truth proof, while
PRs should run focused evidence based on touched behavior and risk.

## Follow-up Specs / Plans

- `USELESSKEY-SPEC-0003` defines stable contract-pack requirements.
- `policy/claim-ledger.toml` maps stable pack claims to proof commands and
  artifacts.
- Release evidence lane specs decide when pack proofs run.
- Future `cargo xtask spec-check` should validate that stable pack claims have
  proof commands, docs, and boundaries.
