+++
id = "USELESSKEY-SPEC-0012"
kind = "spec"
title = "CLI proof handoff boundary"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-15"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = ["USELESSKEY-ADR-0002"]
linked_plan = "plans/first-run-ux/implementation-plan.md"
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0012: CLI Proof Handoff Boundary

## Problem

`uselesskey` now has command-backed public claims, claim-proof receipts, and
metadata-only verification packs. Those proof surfaces are valuable to users,
but they currently live in repo-local `xtask` commands.

The published CLI should eventually give users a product-shaped proof path, but
it must not blur trust boundaries by shelling out to arbitrary `cargo xtask`
commands from whatever directory the user happens to be in. That would make a
user-facing proof command depend on ambient repository state instead of an
owned proof engine.

## Behavior

Until the proof engine has a reusable, owned execution surface, the CLI proof
handoff must be explanatory rather than executable.

The CLI may expose proof discovery through profile commands:

```bash
uselesskey profiles
uselesskey profile webhook --explain
```

Those commands may print:

- the relevant claim id;
- the repo proof command;
- the verification-pack command;
- generated-file posture;
- what the profile proves;
- what it explicitly does not prove.

The CLI must not implement a `prove` command by invoking ambient `cargo xtask`
or shell-evaluating claim-ledger strings.

A future executable CLI proof command is allowed only when one of these is
true:

- proof execution is exposed as a reusable library/API owned by `uselesskey`;
- the CLI can run a packaged proof engine without relying on the caller's
  current repository;
- the command is explicitly scoped to producing instructions or metadata and
  does not claim that proof was executed.

Any future command that writes reviewer evidence must keep verification packs
metadata-only and must not copy generated secret-shaped payloads into the
review bundle.

## Non-goals

This spec does not require `uselesskey prove`.

This spec does not move `claim-proof`, `verification-pack`, or release evidence
out of `xtask`.

This spec does not add a new public claim, contract pack, badge, or release
lane.

This spec does not permit arbitrary command execution from TOML ledgers,
profile metadata, environment variables, or CLI arguments.

## Required Evidence

The current accepted evidence is:

```bash
cargo test -p uselesskey-cli --all-features profile
cargo xtask docs-sync --check
cargo xtask typos
cargo xtask spec-check --strict
git diff --check
```

If a future executable proof command lands, it must add focused CLI tests for
that command and keep the existing `cargo xtask verification-pack --out <dir>`
receipts as the reference proof surface until the release-evidence lane is
updated.

## Acceptance

- `uselesskey profiles` and `uselesskey profile <name> --explain` provide a
  user-facing proof handoff for supported profiles.
- The CLI does not execute repo-local `xtask` proof commands.
- The docs point users to the existing `cargo xtask verification-pack` and
  `cargo xtask claim-proof` commands when they need actual receipts.
- The active first-run UX lane records that executable CLI proof is deferred
  until the proof engine has a safe reusable surface.
- Reviewer evidence remains metadata-only.

## Current v0.10.0 Buildout Decision

The v0.10.0 external-adoption buildout chooses the explanatory handoff path.
The installed CLI may generate, verify, inspect, and explain bundles, but it
does not add `uselesskey prove`.

The durable explanation is
[`docs/explanation/cli-proof-handoff-boundary.md`](../explanation/cli-proof-handoff-boundary.md).
Executable claim proof remains in repo-local `cargo xtask claim-proof` and
metadata-only reviewer bundles remain in `cargo xtask verification-pack`.

## Acceptance Examples

Acceptable:

```text
uselesskey profile webhook --explain
  -> prints cargo xtask claim-proof --claim webhook-contract-pack
  -> prints cargo xtask verification-pack --out ...
  -> says what webhook fixtures do and do not prove
```

Not acceptable:

```text
uselesskey prove --claim webhook-contract-pack
  -> runs cargo xtask verification-pack in the current directory
```

Not acceptable:

```text
uselesskey prove
  -> reads policy/claim-ledger.toml and shell-executes proof_commands strings
```

## Test Mapping

Current coverage:

- CLI profile-discovery unit tests cover rendered proof commands and boundary
  text.
- CLI integration tests cover `profiles` and `profile webhook` stdout.
- `cargo xtask spec-check --strict` validates this accepted spec and its linked
  plan.

Future executable proof work must add integration tests that prove the command
does not copy generated payloads into reviewer evidence.

## Implementation Mapping

Current implementation owners:

- `crates/uselesskey-cli/src/main.rs` owns profile discovery and proof handoff
  text.
- `docs/how-to/start-here.md` owns the first-run user path.
- `docs/contract-packs/README.md` owns product-family proof rows.
- `xtask/src/claim_proof.rs` owns runnable claim-proof receipts.
- `xtask/src/verification_pack.rs` owns metadata-only verification packs.

Future executable CLI proof work should either reuse a shared proof library or
make a separate design decision before adding command execution.

## CI Proof

This handoff boundary is proven by:

```bash
cargo test -p uselesskey-cli --all-features profile
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

The actual reviewer-evidence proof remains:

```bash
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
```

## Metrics / Promotion Rule

This spec can remain accepted while the CLI exposes proof discovery but not
proof execution.

Promote to implemented when:

- profile discovery is shipped in a released CLI;
- user docs clearly route proof execution to `cargo xtask verification-pack`;
- no CLI command claims to execute proof without an owned proof engine.

A future CLI proof runner requires updating this spec, CLI tests, verification
docs, and release evidence before it can become part of a public claim.
