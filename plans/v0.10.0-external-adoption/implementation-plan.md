+++
id = "USELESSKEY-PLAN-0018"
kind = "plan"
title = "v0.10.0 external adoption and installed-user workflows"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-17"
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

# v0.10.0 External Adoption and Installed-User Workflows

## Objective

Make `uselesskey` useful from outside the repo.

The target experience is:

```text
pick job
  -> copy snippet
    -> generate fixture
      -> inspect or verify bundle
        -> understand boundary
          -> optionally produce proof or reviewer artifact
```

This is a buildout lane for the eventual v0.10.0 product-quality target. It is
not release preparation.

## Scope

This lane covers:

- clean-project external adoption smoke for local path mode;
- published-version external adoption smoke as an audit/reference mode;
- installed CLI documentation separated from repo-local proof documentation;
- clean-project examples for webhook, OIDC/JWKS, TLS, and Rust test fixtures;
- CLI profile, bundle explain, and inspect output polish;
- a documented decision for whether proof remains repo-local or gets a safe
  installed CLI handoff;
- optional adoption-regression integration behind an explicit external flag;
- lane closeout with no release action.

## Non-goals

Do not mix these into this lane:

- v0.10.0 release prep;
- version bumps;
- tags or crates.io publish;
- new contract packs;
- new README badges;
- shipper migration work;
- provider compatibility claims;
- production security claims;
- broad refactors;
- dependency churn.

## PR Sequence

1. `ops: start v0.10.0 external adoption lane`
   - Open `.uselesskey/goals/active.toml` for this lane.
   - Add this plan area.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

2. `docs(spec): define external adoption smoke`
   - Add `docs/specs/USELESSKEY-SPEC-0013-external-adoption-smoke.md`.
   - Define clean temp project behavior, local path mode, published-version
     mode, installed CLI mode, dependency-snippet mode, expected generated
     files, proof boundaries, and failure reporting.
   - Update this plan and the active goal to link `USELESSKEY-SPEC-0013`.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

3. `xtask: add external-adoption-smoke`
   - Add:

     ```bash
     cargo xtask external-adoption-smoke --path .
     cargo xtask external-adoption-smoke --path . --format json
     cargo xtask external-adoption-smoke --version 0.9.1
     ```

   - Treat `--path .` as the primary buildout mode.
   - Treat `--version <published>` as an audit/reference mode, not a release
     trigger.
   - Write receipts:

     ```text
     target/external-adoption-smoke/report.md
     target/external-adoption-smoke/report.json
     ```

   - Validation:

     ```bash
     cargo test -p xtask external_adoption_smoke
     cargo xtask external-adoption-smoke --path .
     cargo xtask external-adoption-smoke --path . --format json
     cargo xtask pr-lite
     git diff --check
     ```

4. `docs: separate installed CLI and repo proof paths`
   - Update first-run and contract-pack docs to label paths clearly:
     installed CLI, Rust dependency, repo checkout proof, reviewer evidence, and
     maintainer/agent evidence.
   - Avoid leading user-facing first-run paths with `cargo xtask`.
   - Keep proof boundaries visible through links and short "does not prove"
     sections.
   - Validation:

     ```bash
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

5. `examples: add clean-project adoption examples`
   - Add small downstream-shaped examples:

     ```text
     examples/external/webhook-verifier
     examples/external/oidc-jwks-validation
     examples/external/tls-chain-validation
     examples/external/rust-test-fixtures
     ```

   - Each example should include `Cargo.toml`, source or tests, `README.md`,
     and expected commands.
   - Wire examples into `external-adoption-smoke`.
   - Validation:

     ```bash
     cargo xtask external-adoption-smoke --path .
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

6. `feat(cli): improve bundle/profile inspect output`
   - Improve:

     ```bash
     uselesskey profiles
     uselesskey profile webhook --explain
     uselesskey bundle --profile webhook --explain
     uselesskey inspect-bundle --path target/uselesskey-webhook
     ```

   - Output should answer: what files exist, which files are scanner-safe,
     which files are runtime material, which proof path applies, and what this
     does not prove.
   - Add snapshot or golden coverage where practical.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features profile
     cargo xtask external-adoption-smoke --path .
     cargo xtask pr-lite
     cargo xtask pr
     git diff --check
     ```

7. `docs(design): decide installed proof handoff boundary`
   - Decide whether proof remains repo-local or gets a safe installed CLI
     handoff.
   - If the lane chooses an installed command, the target shape is:

     ```bash
     uselesskey prove --bundle <path> --out <path>
     ```

   - Any installed proof handoff must be metadata-only, non-executable,
     bundle-local, and must not copy raw fixture payloads or execute arbitrary
     claim commands.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

8. `xtask: wire external adoption into adoption-regression`
   - Keep default `cargo xtask adoption-regression` bounded.
   - Add explicit external mode:

     ```bash
     cargo xtask adoption-regression --external
     ```

   - Validation:

     ```bash
     cargo test -p xtask adoption_regression
     cargo xtask adoption-regression
     cargo xtask adoption-regression --external
     cargo xtask pr-lite
     git diff --check
     ```

9. `docs: close out v0.10.0 external adoption buildout`
   - Add `plans/v0.10.0-external-adoption/closeout.md`.
   - Add `docs/learnings/2026-05-v0.10.0-external-adoption.md`.
   - Archive `.uselesskey/goals/active.toml`.
   - Validation:

     ```bash
     cargo xtask external-adoption-smoke --path .
     cargo xtask adoption-regression
     cargo xtask docs-sync --check
     cargo xtask pr-lite
     cargo xtask pr
     git diff --check
     ```

## Acceptance

A new user can get value without cloning the repo:

- install the CLI or add the crate as a dependency;
- copy a documented command or snippet;
- generate scanner-safe, TLS, OIDC/JWKS, or webhook fixtures;
- verify or inspect generated bundles;
- see what the path proves and what it does not prove.

A maintainer can prove those copied paths in a clean project:

- local path mode exercises the current checkout without hidden workspace state;
- published-version mode exercises a crates.io version without implying a
  release action;
- receipts make failures concrete and reviewable.

## Proof Commands

Docs-only lane setup:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

External adoption proof:

```bash
cargo xtask external-adoption-smoke --path .
cargo xtask external-adoption-smoke --path . --format json
cargo xtask external-adoption-smoke --version 0.9.1
```

Regression and PR proof:

```bash
cargo xtask adoption-regression
cargo xtask adoption-regression --external
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

## Rollback

Before code lands, revert the lane-open PR or archive the active goal with a
superseded closeout note.

After xtask or CLI changes land, revert the smallest failing PR or split the
external smoke path into a narrower local-path-only proof. Do not loosen
scanner-safe or claim boundaries to keep the lane moving.

## Stop Conditions

Pause or split the lane if:

- the work starts preparing or cutting v0.10.0;
- a proof command requires a version bump, tag, publish, or shipper migration;
- installed proof would need to shell-evaluate claim ledger strings;
- proof output would copy generated secret-shaped payloads;
- docs imply provider compatibility or production security assurance;
- a new contract pack, badge, dependency churn, or broad refactor becomes
  necessary.
