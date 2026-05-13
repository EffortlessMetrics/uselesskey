+++
id = "USELESSKEY-PLAN-0001"
kind = "plan"
title = "Spec-system rollout"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0001",
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0004",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0007",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
+++

# Spec-System Rollout

## Objective

Make proposals, specs, ADRs, implementation plans, active goal manifests, claim
ledgers, and generated evidence endpoints the normal operating model for
`uselesskey`.

The lane keeps public claims traceable:

```text
README claim -> claim ledger -> spec -> proof command -> artifact or badge
-> release evidence -> user doc -> active goal or archived closeout
```

## Scope

This plan covers source-of-truth docs, claim-ledger mapping, active agent state,
and the future `cargo xtask spec-check` command.

It includes:

- source-of-truth specs and ADRs;
- `policy/claim-ledger.toml`;
- `.uselesskey/goals/active.toml`;
- standalone `cargo xtask spec-check`;
- later wiring into docs, PR, and release evidence;
- lane closeout and learning record.

## Non-goals

Do not mix these into the spec-system lane:

- new bundle profiles;
- TLS mTLS, revocation, CT, or browser trust-store behavior;
- shipper re-migration;
- no-panic burndown;
- dependency churn;
- compatibility-shim churn;
- unrelated SRP refactors;
- automatic badge-refresh workflow changes.

## PR Sequence

Completed:

1. Define the source-of-truth scaffold.
2. Add `USELESSKEY-PROP-0001`.
3. Add `USELESSKEY-SPEC-0001`.
4. Add `USELESSKEY-SPEC-0002` and `policy/claim-ledger.toml`.
5. Add `USELESSKEY-SPEC-0003` and `USELESSKEY-ADR-0001`.
6. Add `USELESSKEY-SPEC-0004` and `USELESSKEY-ADR-0002`.

7. Add `USELESSKEY-SPEC-0005`, `USELESSKEY-ADR-0003`,
   `.uselesskey/goals/active.toml`, and this plan.
8. Add `USELESSKEY-SPEC-0006` for release evidence lanes.
9. Add `USELESSKEY-SPEC-0007` for PR review evidence.
10. Add `USELESSKEY-ADR-0004` for README badge front-panel policy.
11. Add standalone `cargo xtask spec-check`.

Remaining:

12. Wire `spec-check` into docs and PR evidence.
13. Wire `spec-check` into patch and minor release evidence.
14. Close out the lane with a learning record and archived or updated active
    goal manifest.

## Proof Commands

Docs-only spec-system PRs:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Generated endpoint PRs:

```bash
cargo xtask badges --check
cargo test -p xtask badge
```

Contract-pack proof PRs:

```bash
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
```

Future enforcement PRs:

```bash
cargo test -p xtask spec_check
cargo xtask spec-check
cargo xtask spec-check --format json
cargo xtask pr
```

Final lane proof:

```bash
cargo xtask badges --check
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask pr
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
```

## Rollback

Each PR is docs-only or tooling-only. If a docs PR needs rollback, revert that
PR without changing product code.

If `spec-check` is too strict during rollout, keep it standalone until the
shape settles. Do not wire it into PR or release evidence until standalone
validation is stable.

## Stop Conditions

Pause and ask for direction if:

- a spec requires product behavior outside this lane;
- active work would require new fixture profiles or TLS expansion;
- `spec-check` would need to relax existing claim boundaries to pass;
- release, publish, or tag operations become necessary;
- unrelated SRP/refactor PRs appear and cannot be clearly parked.
