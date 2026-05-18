+++
id = "USELESSKEY-PLAN-0020"
kind = "plan"
title = "Installed bundle audit and reviewer handoff"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0012",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
]
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
]
+++

# Installed Bundle Audit and Reviewer Handoff

## Objective

Make installed CLI-generated bundles locally auditable and reviewer-friendly
without requiring a repo checkout or `xtask` proof machinery.

The target experience is:

```text
generate bundle
  -> verify bundle
    -> inspect bundle
      -> audit bundle
        -> attach metadata-only audit receipts
```

This is a v0.10.0 product-quality buildout lane. It is not release
preparation.

## Scope

This lane covers:

- an installed bundle audit spec and boundary;
- deterministic JSON and Markdown audit receipts;
- `uselesskey audit-bundle --path <bundle> --out <dir>`;
- `uselesskey audit-bundle --path <bundle> --format json`;
- profile-specific audit checks for existing scanner-safe, TLS, OIDC, webhook,
  and runtime bundles;
- external-adoption smoke integration so installed-style workflows exercise
  generate, verify, audit, and inspect;
- reviewer handoff docs and a downstream CI recipe;
- closeout with no release action.

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
- dependency churn;
- installed CLI execution of repo-local `xtask` proof;
- claim-ledger command execution from the installed CLI;
- copying raw generated fixture payloads into audit packets.

## PR Sequence

1. `ops: start installed bundle audit lane`
   - Open `.uselesskey/goals/active.toml` for this lane.
   - Add this plan area.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

2. `docs(spec): define installed bundle audit`
   - Add `docs/specs/USELESSKEY-SPEC-0014-installed-bundle-audit.md`.
   - Define audit command shape, metadata-only receipts, profile-neutral
     checks, profile-specific checks, forbidden behavior, claim boundary, and
     stable failure classes.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

3. `feat(cli): add audit-bundle receipt model`
   - Add deterministic JSON and Markdown models for installed bundle audit
     receipts.
   - Keep paths relative to the audited bundle where possible.
   - Do not include raw fixture payload bytes or text in receipts.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features audit_bundle
     cargo xtask pr-lite
     git diff --check
     ```

4. `feat(cli): add audit-bundle command`
   - Add:

     ```bash
     uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit
     uselesskey audit-bundle --path target/uselesskey-webhook --format json
     ```

   - Generic checks cover manifest parse, path containment, listed artifacts,
     receipts, scanner-safe/runtime-material metadata, and unexpected files.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features audit_bundle
     cargo run -p uselesskey-cli -- bundle --profile webhook --out target/audit-test/webhook
     cargo run -p uselesskey-cli -- audit-bundle --path target/audit-test/webhook --out target/audit-test/webhook-audit
     cargo run -p uselesskey-cli -- audit-bundle --path target/audit-test/webhook --format json
     cargo xtask no-blob
     cargo xtask pr-lite
     git diff --check
     ```

5. `feat(cli): add contract-pack audit checks`
   - Add bounded checks for existing profiles only: scanner-safe, TLS, OIDC,
     webhook, and runtime.
   - Do not turn audit into provider compatibility or production security
     proof.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features audit_bundle
     cargo xtask external-adoption-smoke --path .
     cargo xtask adoption-regression --external
     cargo xtask no-blob
     cargo xtask pr-lite
     git diff --check
     ```

6. `xtask: audit generated bundles in external-adoption-smoke`
   - Wire installed-style audit into scanner-safe, TLS, OIDC, and webhook CLI
     smoke paths.
   - External smoke should now prove `bundle -> verify-bundle -> audit-bundle
     -> inspect-bundle`.
   - Validation:

     ```bash
     cargo xtask external-adoption-smoke --path .
     cargo xtask external-adoption-smoke --path . --format json
     cargo xtask adoption-regression --external
     cargo xtask pr-lite
     git diff --check
     ```

7. `docs: add installed bundle audit reviewer handoff`
   - Add reviewer handoff docs and downstream CI docs.
   - Update start-here, contract-pack, verification, and external-example docs
     where they should mention installed audit receipts.
   - Validation:

     ```bash
     cargo xtask docs-sync --check
     cargo xtask typos
     cargo xtask external-adoption-smoke --path .
     git diff --check
     ```

8. `docs: close out installed bundle audit lane`
   - Add closeout and learning record.
   - Archive `.uselesskey/goals/active.toml`.
   - Validation:

     ```bash
     cargo xtask external-adoption-smoke --path .
     cargo xtask adoption-regression --external
     cargo xtask claim-report --check-public-claims
     cargo xtask contract-packs --check
     cargo xtask docs-sync --check
     cargo xtask typos
     cargo +nightly xtask pr-lite
     cargo xtask pr
     git diff --check
     ```

## Stop Conditions

Stop rather than broadening the lane if:

- audit requires new fixture profiles or new public claims;
- a proposed proof command would execute repo-local `xtask` or claim-ledger
  command strings from the installed CLI;
- audit receipts need to copy raw generated payloads;
- the work drifts into release prep, version bump, tag, publish, or badges.
