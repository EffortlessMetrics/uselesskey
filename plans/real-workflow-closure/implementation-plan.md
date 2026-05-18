+++
id = "USELESSKEY-PLAN-0024"
kind = "plan"
title = "Real workflow closure"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0011",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0016",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
+++

# Real Workflow Closure

## Objective

Make `uselesskey` feel less like a well-governed fixture repo and more like a
tool users reach for when auth, TLS, token, webhook, or secret-shaped tests need
deterministic valid and invalid artifacts.

The target experience is:

```text
pick a job
  -> copy one command or snippet
    -> get valid and invalid fixture material
      -> verify or audit the bundle
        -> understand the proof boundary
```

This is a v0.10.0 product-quality buildout lane. It is not release
preparation.

## Scope

This lane covers:

- a real user workflow contract for Rust developer, CI/platform, and explicit
  materialization paths;
- a first-class negative fixture taxonomy;
- taxonomy-backed JWK/JWKS and token-shape negative fixture gaps;
- one downstream OIDC/JWKS validator workflow example;
- a bundle product-surface spec for manifest and receipt contracts;
- tighter bundle manifest and receipt proof where needed;
- task-first docs for common fixture jobs;
- public crate surface discipline so public crates remain user promises.

## Planned Specs

This lane adds the following specs:

```text
USELESSKEY-SPEC-0015-real-user-workflows.md
USELESSKEY-SPEC-0016-negative-fixture-taxonomy.md
USELESSKEY-SPEC-0017-bundle-product-surface.md
USELESSKEY-SPEC-0018-task-first-docs.md
USELESSKEY-SPEC-0019-public-surface-discipline.md
```

Later spec PRs must update this plan and the active goal as each remaining spec
lands.

## Non-goals

Do not mix these into this lane:

- v0.10.0 release prep;
- version bumps;
- tags or crates.io publish;
- new contract packs before negative-fixture and bundle rails are stable;
- new README badges;
- shipper migration work;
- provider compatibility claims;
- production security claims;
- scanner-evasion language;
- installed CLI execution of `xtask` or claim-ledger commands;
- broad SRP refactors;
- dependency churn.

## PR Sequence

1. `ops: start real workflow closure lane`
   - Open `.uselesskey/goals/active.toml` for this lane.
   - Add this plan area.
   - Update `plans/README.md`.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

2. `docs(spec): define real user workflow contract`
   - Add `docs/specs/USELESSKEY-SPEC-0015-real-user-workflows.md`.
   - Define Rust developer, CI/platform, and materialization workflows.
   - Each workflow must have one copyable command or Rust snippet, one positive
     case, one negative case, one verification command, one receipt or smoke
     path, and one boundary.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

3. `docs(spec): define negative fixture taxonomy`
   - Add `docs/specs/USELESSKEY-SPEC-0016-negative-fixture-taxonomy.md`.
   - Cover JWK, JWKS, JWT/token, webhook, and X.509 negative fixture families.
   - A negative fixture must be deterministic, scanner-safe unless explicitly
     materialized, tied to a realistic downstream parser/verifier failure, tested
     for intended shape, and documented by failure mode.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

4. `feat(jwk): add realistic JWK and JWKS negative fixtures`
   - Implement only taxonomy-backed JWK/JWKS cases.
   - Preserve deterministic fixture identity for existing fixtures.
   - Validation:

     ```bash
     cargo test -p uselesskey-jwk --all-features
     cargo test -p uselesskey --all-features
     cargo +nightly xtask pr-lite
     git diff --check
     ```

5. `feat(token): add realistic token negative fixtures`
   - Cover bad segment count, malformed base64url, `alg: none`, missing `kid`,
     expired/`nbf`, bad `aud`/`iss`, and scanner-safe malformed bearer/API token
     shapes where they match the taxonomy.
   - Validation:

     ```bash
     cargo test -p uselesskey-token --all-features
     cargo test -p uselesskey --all-features
     cargo +nightly xtask pr-lite
     git diff --check
     ```

6. `examples: add OIDC JWKS validator workflow`
   - Add a downstream-shaped OIDC/JWKS validator example with valid JWKS and
     duplicate-kid, wrong-kty, and unsupported-alg negatives.
   - Prove users can test auth validation without managing real keys.
   - Validation:

     ```bash
     cargo xtask external-adoption-smoke --path .
     cargo xtask adoption-regression --external
     git diff --check
     ```

7. `docs(spec): define bundle product surface`
   - Add `docs/specs/USELESSKEY-SPEC-0017-bundle-product-surface.md`.
   - Define manifest and receipt contracts before broad emitter expansion.
   - Do not implement every future emitter in this PR.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

8. `feat(cli): add bundle manifest verification receipt`
   - Add or tighten `bundle-verification`, `scanner-safety`, and
     `negative-coverage` receipts where the bundle product-surface spec requires
     them.
   - Keep receipts metadata-only.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features bundle verify_bundle audit_bundle
     cargo xtask external-adoption-smoke --path .
     cargo xtask no-blob
     cargo +nightly xtask pr-lite
     git diff --check
     ```

9. `docs: add task-first fixture workflows`
   - Add `docs/specs/USELESSKEY-SPEC-0018-task-first-docs.md`.
   - Add or update task-first how-tos for OIDC/JWKS validation, JWT claim
     validation, scanner-safe Kubernetes secrets, build-time RSA
     materialization, and bundle verification.
   - Each page must include install/dependency line, copyable command or code,
     expected output, scanner-safety note, failure mode, exact verification
     command, and boundary.
   - Validation:

     ```bash
     cargo xtask docs-sync --check
     cargo xtask typos
     cargo xtask external-adoption-smoke --path .
     git diff --check
     ```

10. `docs: define public crate surface promises`
    - Add `docs/specs/USELESSKEY-SPEC-0019-public-surface-discipline.md`.
    - Add a public surface matrix that answers who imports each public crate,
      what job it solves, which docs prove that job, required feature flags, and
      stability promise.
    - Mark crates without a downstream import story as candidate-internal rather
      than expanding user promises by accident.
    - Validation:

      ```bash
      cargo xtask public-surface
      cargo xtask docs-sync --check
      cargo xtask typos
      git diff --check
      ```

11. `docs: close out real workflow closure lane`
    - Add `plans/real-workflow-closure/closeout.md`.
    - Add `docs/learnings/2026-05-real-workflow-closure.md`.
    - Archive `.uselesskey/goals/active.toml`.
    - Validation:

      ```bash
      cargo xtask external-adoption-smoke --path . --format json
      cargo xtask adoption-regression --external
      cargo xtask claim-report --check-public-claims
      cargo xtask contract-packs --check
      cargo xtask check-no-panic-family
      cargo xtask docs-sync --check
      cargo xtask typos
      cargo +nightly xtask pr-lite
      cargo xtask pr
      git diff --check
      ```

## Review Rails

Every PR should make these points explicit:

```text
User path:
  What user job does this improve?

Boundary:
  What does this not prove?

Proof:
  Which command proves it?

Receipts:
  Which artifact changed or was added?

Risk:
  Does this change deterministic fixture identity?

Rollback:
  Can this PR be reverted without invalidating later receipts?
```

## Acceptance

The lane is complete when a user can:

- pick a Rust test, CI/platform bundle, or materialization job;
- copy one command or snippet;
- get deterministic valid and invalid fixture material;
- verify or audit the generated bundle;
- attach metadata-only receipts when needed;
- understand scanner-safety and "does not prove" boundaries without learning
  the repo operating system.

## Proof Commands

Docs-only lane setup:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation and closeout proof:

```bash
cargo xtask external-adoption-smoke --path . --format json
cargo xtask adoption-regression --external
cargo +nightly xtask pr-lite
cargo xtask pr
git diff --check
```

## Rollback

Before code lands, revert the lane-open PR or archive the active goal with a
superseded closeout note.

After implementation lands, revert the smallest failing PR. Do not loosen
deterministic fixture identity, scanner-safe defaults, metadata-only receipts,
or claim boundaries to keep the lane moving.

## Stop Conditions

Pause or split the lane if:

- the work starts preparing or cutting v0.10.0;
- a proof command requires a version bump, tag, publish, or shipper migration;
- a doc or implementation implies provider compatibility, production security,
  or scanner-evasion behavior;
- an installed CLI command needs to execute repo-local `xtask` or claim-ledger
  commands;
- a receipt needs to copy generated secret-shaped payloads;
- new contract packs, badges, dependency churn, or broad refactors become
  necessary.
