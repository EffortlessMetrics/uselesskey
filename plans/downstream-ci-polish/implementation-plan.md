+++
id = "USELESSKEY-PLAN-0022"
kind = "plan"
title = "Downstream CI and installed-user polish"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0005",
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

# Downstream CI and Installed-User Polish

## Objective

Make the installed bundle loop boring to run every day in downstream CI.

The target experience is:

```text
install
  -> generate
    -> verify
      -> inspect
        -> audit
          -> fail CI on stable failure classes
            -> attach metadata-only evidence
```

This is a v0.10.0 product-quality buildout lane. It is not release
preparation.

## Scope

This lane covers:

- a documented stable JSON contract for installed bundle audit receipts;
- CI-oriented audit behavior that downstream users can rely on without parsing
  prose;
- downstream GitHub Actions recipes for generate, verify, audit, and artifact
  upload;
- explicit external-adoption smoke for documented CI recipes;
- clearer `audit-bundle` failure diagnostics with stable failure classes;
- a small installed-user `uselesskey doctor` command;
- consistent `inspect-bundle` and `audit-bundle` wording;
- one downstream-shaped CI example for bundle audit;
- golden coverage for stable audit receipt shape and boundary language;
- compact audit summaries for terminal and CI logs;
- closeout with no release action.

## Non-goals

Do not mix these into this lane:

- v0.10.0 release prep;
- version bumps;
- tags or crates.io publish;
- new contract packs;
- new README badges;
- badge work except generated endpoint drift caused by this lane's checks;
- shipper migration work;
- provider compatibility claims;
- production security claims;
- scanner-evasion language;
- broad refactors;
- dependency churn.

## PR Sequence

1. `ops: start downstream CI polish lane`
   - Open `.uselesskey/goals/active.toml` for this lane.
   - Add this plan area.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

2. `docs(spec): define bundle audit JSON schema`
   - Add:

     ```text
     docs/schemas/bundle-audit.schema.json
     docs/reference/bundle-audit-json.md
     ```

   - Document stable fields including schema version, status, bundle path,
     profile, artifacts, checks, failure classes, and boundaries.
   - Keep failure classes stable:

     ```text
     missing_manifest
     invalid_manifest
     path_escape
     missing_artifact
     unexpected_artifact
     missing_receipt
     invalid_receipt
     scanner_safe_mismatch
     runtime_material_mismatch
     profile_validation_failed
     unsupported_profile
     ```

   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features audit_bundle
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

3. `feat(cli): add audit-bundle CI policy controls`
   - Add CI-oriented behavior such as:

     ```bash
     uselesskey audit-bundle --path target/uselesskey-webhook --ci
     ```

   - Preserve:

     ```text
     exit 0: bundle audit passed
     exit 1: audit failed by stable class
     exit 2: CLI/config usage error
     ```

   - Avoid requiring downstream shell parsing of human prose.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features audit_bundle
     cargo run -p uselesskey-cli -- audit-bundle --path target/audit-test/webhook --ci
     cargo xtask external-adoption-smoke --path . --format json
     cargo +nightly xtask pr-lite
     git diff --check
     ```

4. `docs: add downstream CI recipes for bundle audit`
   - Add:

     ```text
     docs/how-to/use-uselesskey-in-github-actions.md
     ```

   - Include recipes for webhook fixtures, TLS/OIDC fixtures, and uploading
     `bundle-audit.json` plus `bundle-audit.md` as CI artifacts.
   - State that installed audit proves local generated bundle consistency, not
     production security or provider compatibility.
   - Validation:

     ```bash
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

5. `xtask: test downstream CI snippets`
   - Extend external adoption smoke with explicit documented recipe mode:

     ```bash
     cargo xtask external-adoption-smoke --path . --ci-recipes
     ```

   - Keep default external smoke bounded.
   - Validation:

     ```bash
     cargo test -p xtask external_adoption_smoke
     cargo xtask external-adoption-smoke --path . --ci-recipes --format json
     cargo xtask adoption-regression --external
     git diff --check
     ```

6. `feat(cli): improve audit-bundle failure diagnostics`
   - Make human failures copyable and actionable while preserving stable JSON
     failure classes.
   - Do not print raw fixture payloads.
   - Keep paths relative where possible.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features audit_bundle
     cargo xtask no-blob
     cargo +nightly xtask pr-lite
     git diff --check
     ```

7. `feat(cli): add installed CLI doctor`
   - Add:

     ```bash
     uselesskey doctor
     uselesskey doctor --format json
     ```

   - Check installed-user concerns only: CLI version, current working
     directory, `target/` write access, bundle output path safety, JSON output
     support, and known profiles.
   - Do not check repo-local proof tools.
   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features doctor
     cargo run -p uselesskey-cli -- doctor
     cargo run -p uselesskey-cli -- doctor --format json
     cargo +nightly xtask pr-lite
     git diff --check
     ```

8. `feat(cli): align inspect-bundle and audit-bundle summaries`
   - Keep `inspect-bundle` as a quick human summary.
   - Keep `audit-bundle` as durable metadata-only reviewer and CI receipts.
   - Add:

     ```text
     docs/reference/bundle-inspect-vs-audit.md
     ```

   - Validation:

     ```bash
     cargo test -p uselesskey-cli --all-features inspect audit_bundle
     cargo xtask external-adoption-smoke --path .
     cargo xtask docs-sync --check
     git diff --check
     ```

9. `examples: add downstream CI bundle audit example`
   - Add:

     ```text
     examples/external/downstream-ci-bundle-audit/
       Cargo.toml
       README.md
       .github/workflows/uselesskey-audit.yml.example
     ```

   - Model the installed loop:

     ```bash
     uselesskey bundle --profile webhook --out target/uselesskey-webhook
     uselesskey verify-bundle --path target/uselesskey-webhook
     uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit
     ```

   - Validation:

     ```bash
     cargo xtask external-adoption-smoke --path .
     cargo xtask adoption-regression --external
     git diff --check
     ```

10. `test(cli): add audit receipt golden coverage`
    - Golden-test stable parts of:

      ```text
      bundle-audit.md
      bundle-audit.json
      ```

    - Normalize volatile paths.
    - Protect schema shape, boundary language, and metadata-only posture.
    - Validation:

      ```bash
      cargo test -p uselesskey-cli --all-features audit_bundle
      cargo xtask no-blob
      cargo +nightly xtask pr-lite
      git diff --check
      ```

11. `feat(cli): add compact audit summary output`
    - Add:

      ```bash
      uselesskey audit-bundle --path target/uselesskey-webhook --summary
      ```

    - Keep output compact for terminals and CI logs.
    - Validation:

      ```bash
      cargo test -p uselesskey-cli --all-features audit_bundle
      cargo xtask external-adoption-smoke --path .
      git diff --check
      ```

12. `docs: close out downstream CI polish lane`
    - Add closeout and learning record.
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

## Acceptance

A downstream team can:

- install `uselesskey-cli`;
- generate scanner-safe, TLS, OIDC, or webhook fixtures;
- verify and inspect the bundle;
- audit the bundle with installed CLI commands;
- fail CI on stable failure classes;
- upload metadata-only audit receipts;
- understand what audit proves and what remains out of scope.

## Proof Commands

Docs-only lane setup:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

External and CI-loop proof:

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

After CLI or xtask changes land, revert the smallest failing PR. Do not loosen
audit boundaries, scanner-safe classification, or failure-class stability to
keep the lane moving.

## Stop Conditions

Pause or split the lane if:

- the work starts preparing or cutting v0.10.0;
- a change requires a version bump, tag, publish, or shipper migration;
- a CI recipe implies provider compatibility, production security, or scanner
  evasion;
- installed CLI commands need to execute repo-local `xtask` or claim-ledger
  command strings;
- audit receipts need to copy raw generated fixture payloads;
- a new contract pack, new badge, dependency churn, or broad refactor becomes
  necessary.
