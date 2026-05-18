# Specs

Specs define what `uselesskey` promises and how that promise is proven. They are
behavior contracts, not implementation journals.

A spec should make a public claim auditable:

```text
claim -> behavior -> non-goals -> proof command -> receipt -> user doc
```

## Required Shape

Use [the spec template](../templates/spec.md). Each accepted spec should include:

- Problem
- Behavior
- Non-goals
- Required evidence
- Acceptance
- Acceptance examples
- Test mapping
- Implementation mapping
- CI proof
- Metrics or promotion rule

Do not claim enforcement until `cargo xtask spec-check` exists and is wired into
the relevant evidence lane.

## Examples To Keep Concrete

Good examples for this repo are scanner-safe fixtures, TLS contract packs,
OIDC/JWKS validation fixtures, `ripr+` badge endpoints, crates.io smoke, and
public crate-surface cleanup.

## Current Specs

- [USELESSKEY-SPEC-0001: Source-of-truth model](USELESSKEY-SPEC-0001-source-of-truth-model.md)
- [USELESSKEY-SPEC-0002: Public claim ledger](USELESSKEY-SPEC-0002-public-claim-ledger.md)
- [USELESSKEY-SPEC-0003: Contract-pack profile requirements](USELESSKEY-SPEC-0003-contract-pack-profile.md)
- [USELESSKEY-SPEC-0004: Generated evidence endpoints](USELESSKEY-SPEC-0004-generated-evidence-endpoints.md)
- [USELESSKEY-SPEC-0005: Agent lane state](USELESSKEY-SPEC-0005-agent-lane-state.md)
- [USELESSKEY-SPEC-0006: Release evidence lanes](USELESSKEY-SPEC-0006-release-evidence-lanes.md)
- [USELESSKEY-SPEC-0007: PR review evidence](USELESSKEY-SPEC-0007-pr-review-evidence.md)
- [USELESSKEY-SPEC-0008: Claim-proof execution](USELESSKEY-SPEC-0008-claim-proof-execution.md)
- [USELESSKEY-SPEC-0009: Verification-pack receipt bundle](USELESSKEY-SPEC-0009-verification-pack.md)
- [USELESSKEY-SPEC-0010: PR-lite evidence ergonomics](USELESSKEY-SPEC-0010-pr-lite-evidence.md)
- [USELESSKEY-SPEC-0011: Webhook contract pack](USELESSKEY-SPEC-0011-webhook-contract-pack.md)
- [USELESSKEY-SPEC-0012: CLI proof handoff boundary](USELESSKEY-SPEC-0012-cli-proof-handoff.md)
- [USELESSKEY-SPEC-0013: External adoption smoke](USELESSKEY-SPEC-0013-external-adoption-smoke.md)
- [USELESSKEY-SPEC-0014: Installed bundle audit](USELESSKEY-SPEC-0014-installed-bundle-audit.md)
