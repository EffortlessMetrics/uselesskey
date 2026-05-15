+++
id = "USELESSKEY-PLAN-0013"
kind = "plan"
title = "First-run UX and contract-pack adoption"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-15"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
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

# First-Run UX and Contract-Pack Adoption

## Objective

Make `uselesskey` easier to use without weakening its proof boundaries.

The target experience is:

```text
I know which lane I need.
I copy one command or one dependency snippet.
I get a fixture that works.
I can prove what it claims.
I know what it does not claim.
I never have to understand the repo's internal proof machinery unless I choose to.
```

## Scope

This lane covers:

- a task-first "start here" router;
- a visible contract-pack product-family index;
- CLI profile discovery and explanation commands;
- user-facing proof/reviewer handoff commands or a documented spec if direct
  CLI support is not clean yet;
- a local proof-environment doctor for maintainers and agents;
- a compressed README first-run path;
- bounded user-path smoke checks for the documented copy/paste flows;
- lane closeout and learning artifacts.

## Non-Goals

Do not mix these into the first-run UX lane:

- new fixture families or contract packs;
- new crypto or provider compatibility claims;
- new README badges;
- shipper migration work;
- historical no-panic baseline cleanup;
- dependency churn;
- production secret-management, production PKI, replay-protection, or provider
  compatibility promises.

## PR Sequence

1. `ops: start first-run UX lane`
   - Open `.uselesskey/goals/active.toml`.
   - Add this plan area.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

2. `docs: add start-here task router`
   - Add `docs/how-to/start-here.md`.
   - Route from README near the first-run section.
   - Include one command or dependency snippet for each common user job.
   - Validation:

     ```bash
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

3. `docs: make contract packs a visible product family`
   - Add `docs/contract-packs/README.md`.
   - List scanner-safe, TLS, OIDC/JWKS, and webhook profiles.
   - For each row, include generate, verify, proof, what it proves, and what it
     does not prove.
   - Validation:

     ```bash
     cargo xtask contract-packs --check
     cargo xtask claim-report --check-public-claims
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

4. `feat(cli): add profile discovery commands`
   - Add `uselesskey profiles`.
   - Add `uselesskey profile <name> --explain`.
   - Explain generated files, scanner-safe/runtime-material posture, proof
     commands, and claim boundaries.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features profile
     cargo xtask pr-lite
     cargo xtask pr
     git diff --check
     ```

5. `feat(cli): add proof handoff commands`
   - Prefer a user-facing CLI command for reviewer evidence, such as
     `uselesskey prove --claim webhook-contract-pack --out target/uselesskey-verification`.
   - If CLI architecture cannot cleanly own this yet, add the spec and defer the
     command rather than duplicating unsafe proof execution.
   - Current decision: `USELESSKEY-SPEC-0012` defers executable CLI proof until
     the proof engine has a safe reusable surface. The shipped CLI handoff is
     profile discovery text that points to `cargo xtask claim-proof` and
     `cargo xtask verification-pack`.
   - Keep verification packs metadata-only.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features prove
     cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
     cargo xtask no-blob
     cargo xtask pr
     git diff --check
     ```

6. `xtask: add local proof doctor`
   - Add `cargo xtask doctor`.
   - Add `cargo xtask doctor --format json`.
   - Check Rust toolchain, required helper tools, Windows ASAN runtime
     availability, crates.io auth presence, GitHub CLI availability, dirty tree
     state, and generated badge drift.
   - Validation:

     ```bash
     cargo test -p xtask doctor
     cargo xtask doctor
     cargo xtask doctor --format json
     cargo xtask pr-lite
     git diff --check
     ```

7. `docs: compress README first-run path`
   - Keep depth, but move it below a task-first opening.
   - Ensure the first runnable command appears early.
   - Keep proof and claim boundaries visible without forcing users through
     ledgers first.
   - Validation:

     ```bash
     cargo xtask docs-sync --check
     cargo xtask typos
     cargo xtask badges --check
     git diff --check
     ```

8. `xtask: add user-path smoke checks`
   - Add `cargo xtask user-path-smoke`.
   - Exercise bounded documented flows: scanner-safe, TLS, OIDC/JWKS, webhook,
     bundle verification, and webhook verification-pack generation.
   - Validation:

     ```bash
     cargo test -p xtask user_path_smoke
     cargo xtask user-path-smoke
     cargo xtask pr-lite
     git diff --check
     ```

9. `docs: close out first-run UX lane`
   - Add `plans/first-run-ux/closeout.md`.
   - Add `docs/learnings/2026-05-first-run-ux.md`.
   - Archive `.uselesskey/goals/active.toml`.
   - Validation:

     ```bash
     cargo xtask user-path-smoke
     cargo xtask doctor
     cargo xtask docs-sync --check
     cargo xtask pr-lite
     cargo xtask pr
     git diff --check
     ```

## UX Acceptance

A Rust user can answer in under two minutes:

- which feature flags they need;
- what to copy into `Cargo.toml`;
- how to make output deterministic;
- how to avoid committed fixture blobs.

A CLI user can answer in under two minutes:

- which profile they need;
- what files will be generated;
- which files are reviewable metadata;
- which generated payloads belong under `target/`.

A reviewer can answer in under five minutes:

- what the project claims;
- which command proves it;
- what to attach;
- what is explicitly out of scope.

A maintainer or agent can answer before opening a PR:

- whether the local machine can run the proof stack;
- which gate failed;
- whether the failure is code, environment, or generated drift;
- which command reproduces hosted CI.

## Stop Conditions

Pause or split the lane if:

- CLI proof handoff would require shell-evaluating claim-ledger command strings;
- a proof bundle would copy generated secret-shaped payloads instead of
  metadata;
- the UX work creates a new public claim without claim-ledger and proof updates;
- the lane starts adding new contract packs, provider matrices, dependency
  churn, or release machinery.
