+++
id = "USELESSKEY-PLAN-0025"
kind = "plan"
title = "Usability polish"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0012",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0017",
  "USELESSKEY-SPEC-0018",
  "USELESSKEY-SPEC-0019",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
+++

# Usability Polish

## Objective

Make `uselesskey` feel obvious, installable, and usable outside the repo.

The target experience is:

```text
front door
  -> install path
    -> CLI self-check
      -> fixture generation
        -> audit/CI path
          -> Rust facade example
            -> downstream policy/reviewer handoff
```

This is a v0.10.0 product-quality buildout lane. It is not release
preparation.

## Scope

This lane covers:

- install and distribution polish without release execution;
- a sharper README/front-door narrative for core user jobs;
- installed CLI help and `doctor` self-check behavior;
- library facade examples that compile in clean external projects;
- bounded external smoke for facade-first examples;
- downstream policy presets and reviewer checklist guidance;
- tiny `audit-bundle` policy controls only if they remain simple and stable;
- closeout with no version bump, tag, publish, or new contract pack.

## Non-goals

Do not mix these into this lane:

- v0.10.0 release prep;
- version bumps;
- tags or crates.io publish;
- new contract packs;
- WebAuthn, PKCS#11, Vault/Kubernetes, or other fixture breadth work;
- provider compatibility claims;
- production security claims;
- scanner-policy bypass language;
- broad policy DSL;
- broad facade redesign;
- shipper work;
- dependency churn;
- installed CLI execution of `xtask` or claim-ledger commands.

## PR Sequence

0. PR-wave triage
   - Merge only non-overlapping, current, green, useful quality PRs.
   - Close or park redundant PRs with explicit disposition.
   - Do not let quality coverage PRs become product direction.

1. `ops: start usability polish lane`
   - Replace `.uselesskey/goals/active.toml` with this lane.
   - Add this plan area.
   - Add `USELESSKEY-SPEC-0018-install-distribution-polish.md`.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

2. `docs: sharpen README front door`
   - Make the first screen answer:

     ```text
     What does this do?
     What job do I have?
     How do I install or depend on it?
     How do I generate/audit fixtures?
     What does this not prove?
     ```

   - Keep proof machinery behind links.
   - Validation:

     ```bash
     cargo xtask docs-sync --check
     cargo xtask typos
     cargo xtask external-adoption-smoke --path .
     git diff --check
     ```

3. `docs/cli: audit installed help and self-check`
   - Inspect `uselesskey --help`, `uselesskey bundle --help`,
     `uselesskey audit-bundle --help`, and `uselesskey doctor`.
   - Improve wording only where it helps installed users pick the next command.
   - Do not route installed users through `xtask`.

4. `docs(spec): define library facade polish`
   - Add `USELESSKEY-SPEC-0019-library-facade-polish.md`.
   - Define clean-project Rust test author requirements, feature flag
     discoverability, examples, missing-feature diagnostics, and boundaries.

5. `examples: add facade-first external Rust examples`
   - Add small examples that use the `uselesskey` facade crate first.
   - Avoid requiring users to discover leaf crate internals before first value.

6. `xtask: smoke facade-first external examples`
   - Extend external adoption smoke only if it stays bounded.
   - Add an explicit `--library-examples` mode for facade-first clean-project
     examples so library proof does not require the installed CLI bundle loop.
   - Keep published-version mode as audit/reference, not release prep.

7. `docs(spec): define downstream policy pack`
   - Add `USELESSKEY-SPEC-0020-downstream-policy-pack.md`.
   - Define presets such as `strict`, not a broad DSL.

8. `feat(cli): add tiny audit-bundle policy controls`
   - Only implement controls that remain stable and obvious, such as:

     ```bash
     uselesskey audit-bundle --path target/uselesskey-webhook --ci --expect-profile webhook
     uselesskey audit-bundle --path target/uselesskey-webhook --ci --policy strict
     ```

   - Skip this PR if it starts becoming a policy language.

9. `docs: add downstream policy docs and reviewer checklist`
   - Explain what audit receipts prove, what they do not prove, and what a
     reviewer should attach.

10. `docs: close out usability polish lane`
    - Add closeout and learning record.
    - Archive `.uselesskey/goals/active.toml`.

## Acceptance

A downstream user can:

- understand `uselesskey` in one screen;
- install the CLI or add the facade crate as a dev-dependency;
- run an installed self-check;
- generate scanner-safe/TLS/OIDC/webhook fixtures;
- audit the bundle and upload metadata-only receipts in CI;
- use the Rust facade in a clean external test project;
- explain the receipt boundary to a reviewer.

## Proof Commands

Lane setup:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Full closeout:

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

## Stop Conditions

Pause or split the lane if:

- the work starts preparing or cutting v0.10.0;
- a change requires a version bump, tag, publish, or shipper migration;
- a policy feature becomes a broad DSL;
- installed CLI commands need to execute repo-local proof machinery;
- a new fixture family or contract pack becomes necessary;
- a doc claim implies provider compatibility, production security, or scanner
  evasion.
