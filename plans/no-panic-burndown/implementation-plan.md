+++
id = "USELESSKEY-PLAN-0007"
kind = "plan"
title = "No-panic burndown"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0005",
]
linked_adrs = []
+++

# No-Panic Burndown

## Objective

Burn down the no-panic-family debt tracked by issue #575 without resetting the
baseline, weakening policy, or absorbing new debt into the snapshot.

## Source State

Issue #575 is the tracking ticket. Its live snapshot reports:

```text
4307 finding(s)
4157 baselined
150 new-debt
54 stale-baseline
0 expired
mode = no-new-debt
```

The largest clusters are test-code `expect` and `unwrap` sites. The remaining
production-path cluster needs case-by-case review: either remove the panic path
or add a receipted allowlist entry with owner, classification, explanation, and
expiry.

## Scope

This lane covers:

- migration of test-code panic-family sites to `uselesskey-test-support`
  fallible helpers;
- deliberate baseline refreshes with `cargo xtask no-panic baseline` after
  vanished entries are removed;
- case-by-case production-path review;
- receipted allowlist entries only for justified invariants or fixture
  boundaries;
- final policy-stage preparation once no-new-debt is clean.

## Non-Goals

Do not mix these into this lane:

- `cargo xtask no-panic baseline --reset`;
- baseline reset or absorption of new debt;
- weakening `policy/clippy-lints.toml`;
- broad refactors unrelated to panic-family debt;
- new fixture profiles;
- release execution;
- shipper migration work;
- README badge changes;
- dependency churn.

## PR Sequence

1. Open this active lane and implementation plan.
2. Migrate `crates/uselesskey-cli/tests/cli.rs` to fallible test helpers.
3. Migrate xtask tests.
4. Migrate core test modules.
5. Migrate JWK and token test modules.
6. Review remaining production-path findings and either propagate errors or
   add receipted allowlist entries.
7. Flip policy stage only when `check-no-panic-family` is clean and remaining
   exceptions are receipted.
8. Close out the lane with a learning record and archived active goal.

## Proof Commands

Lane-opening PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Per-burndown PR:

```bash
cargo xtask check-no-panic-family
cargo xtask no-panic baseline
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

Use focused crate tests before the broad gate. For example:

```bash
cargo test -p uselesskey-cli --test cli
cargo test -p xtask
cargo test -p uselesskey-core
cargo test -p uselesskey-jwk
cargo test -p uselesskey-token
```

## Stop Conditions

Pause and split work if a PR would require baseline reset, policy weakening,
unrelated refactors, public API changes, release execution, new fixture
profiles, shipper work, or dependency churn.

Do not mark the lane complete until `cargo xtask check-no-panic-family` exits 0
in `no-new-debt` mode without `--reset`.
