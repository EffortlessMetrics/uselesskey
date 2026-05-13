+++
id = "USELESSKEY-PLAN-0003"
kind = "plan"
title = "Claim-backed verification UX"
status = "accepted"
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
  "USELESSKEY-SPEC-0007",
  "USELESSKEY-SPEC-0008",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
+++

# Claim-Backed Verification UX

## Objective

Make `uselesskey`'s public claims discoverable, runnable, and reviewable from
the repo itself.

The intended user path is:

```text
README badge -> docs/reference/verification-badges.md
  -> docs/status/PUBLIC_CLAIMS.md
    -> cargo xtask claim-report
      -> cargo xtask claim-proof --claim <claim>
```

## Scope

This lane turns the completed spec-system into a product-facing verification
surface:

- claim-report Markdown and JSON generated from `policy/claim-ledger.toml`;
- drift checks between `docs/status/PUBLIC_CLAIMS.md` and the claim ledger;
- a task-first public-claim verification guide;
- a contract-pack registry and check command;
- release-evidence rows for claim-report and contract-pack receipts;
- badge and claim-boundary documentation polish;
- an agent bootstrap guide that starts from `.uselesskey/goals/active.toml`;
- a claim-proof execution policy and allowlisted runner for selected stable
  claims;
- a verification-pack receipt bundle for users and reviewers.

## Non-Goals

Do not mix these into this lane:

- new fixture profiles;
- TLS mTLS, revocation, CT, or browser trust-store behavior;
- shipper re-migration;
- no-panic burndown;
- dependency churn;
- compatibility-shim churn;
- new badges unless backed by an existing stable command;
- hand-written generated badge JSON;
- automatic direct-to-main badge writes.

## PR Sequence

1. Open this active lane and implementation plan.
2. Add `cargo xtask claim-report`.
3. Check `docs/status/PUBLIC_CLAIMS.md` against `policy/claim-ledger.toml`.
4. Add `docs/how-to/verify-uselesskey-public-claims.md`.
5. Add `policy/contract-packs.toml` and `cargo xtask contract-packs`.
6. Add claim-report and contract-pack receipts to release evidence.
7. Tighten badge meaning and claim-boundary docs.
8. Add an agent bootstrap guide.
9. Define the claim-proof execution policy.
10. Add an allowlisted `cargo xtask claim-proof` runner.
11. Define the verification-pack receipt bundle.
12. Add `cargo xtask verification-pack`.
13. Wire claim-proof and verification-pack receipts into release evidence.
14. Polish the public verification UX.
15. Close out the lane with a learning record and archived goal manifest.

## Proof Commands

Lane-opening PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Final lane proof:

```bash
cargo xtask spec-check --strict
cargo xtask claim-report
cargo xtask claim-report --format json
cargo xtask contract-packs --check
cargo xtask badges --check
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
```

## Stop Conditions

Pause and split work if a PR would require product behavior, release execution,
new fixture profiles, TLS expansion, dependency churn, or direct-to-main badge
automation.
