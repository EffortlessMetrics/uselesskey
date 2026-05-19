+++
id = "USELESSKEY-SPEC-0020"
kind = "spec"
title = "Downstream policy pack"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-19"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
linked_plan = "plans/usability-polish/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0017",
  "USELESSKEY-SPEC-0018",
]
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0020: Downstream Policy Pack

## Problem

Downstream CI can now generate bundles, verify them, inspect them, audit them,
and fail on stable audit classes. That makes `uselesskey` operationally useful,
but a downstream team still needs a small policy shape:

```text
Which profile did this job expect?
Which audit status should fail CI?
Which metadata-only receipt should be attached?
Which boundary should a reviewer read?
```

The answer should be a small set of presets and checklist docs. It must not
become a broad policy language, a governance engine, or a way to imply
production security.

## Behavior

The downstream policy pack defines preset policy expectations for installed
bundle audit output. Presets are named, bounded, and explainable:

| Preset | Intended user job | Expected behavior |
| --- | --- | --- |
| `default` | Local installed CLI use | Report audit status and stable failure classes without adding stricter CI expectations. |
| `strict` | Downstream CI gate | Fail if audit status is not `pass`, expected profile does not match, required receipts are missing, unexpected files appear, paths escape the bundle root, or scanner-safe/runtime-material counts drift. |
| `reviewer` | Security/platform handoff | Produce or document the metadata-only files to attach and the "does not prove" boundary to include. |

Policy controls should stay tiny. The initial accepted controls are:

```bash
uselesskey audit-bundle --path target/uselesskey-webhook --ci --expect-profile webhook
uselesskey audit-bundle --path target/uselesskey-webhook --ci --policy strict
```

`--expect-profile <profile>` checks that the audited bundle profile matches the
job the downstream CI intended to run.

`--policy strict` applies the built-in strict CI preset. It is not a user-defined
DSL. If a requested behavior needs custom expressions, conditionals, remote
policy fetches, or repository scanning, it is out of scope for this lane.

The policy pack should document the installed-user loop:

```text
generate
  -> verify
    -> inspect
      -> audit --ci --expect-profile <profile> --policy strict
        -> upload bundle-audit.json and bundle-audit.md
        -> attach reviewer checklist when needed
```

Machine-readable JSON remains the contract for CI. Human docs and checklist
language explain what the JSON means without asking users to parse repo-local
proof systems.

## Non-goals

This spec does not:

- prepare, cut, tag, or publish v0.10.0;
- add new contract packs, fixture families, or README badges;
- create a broad policy DSL or organization policy engine;
- load policy from remote URLs or execute policy scripts;
- make provider compatibility, production security, release readiness, or
  scanner-policy bypass claims;
- allow installed CLI commands to execute `xtask`, release evidence, or
  claim-ledger command strings;
- copy raw generated fixture payloads into reviewer or policy receipts.

## Required Evidence

Docs-only policy-pack work must run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation work for tiny policy controls must run:

```bash
cargo test -p uselesskey-cli --all-features audit_bundle
cargo xtask external-adoption-smoke --path .
cargo +nightly xtask pr-lite
git diff --check
```

Docs that add downstream policy recipes must run:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

## Acceptance

This spec is accepted when it defines:

- preset names and boundaries;
- the `strict` preset as a built-in CI policy, not a DSL;
- the `reviewer` handoff shape;
- tiny allowed controls, currently `--expect-profile` and `--policy strict`;
- stable "does not prove" boundaries for policy docs;
- proof commands for docs-only and implementation PRs.

This spec is implemented when:

- `audit-bundle --ci --expect-profile <profile>` fails on profile mismatch;
- `audit-bundle --ci --policy strict` applies the strict built-in checks;
- downstream policy docs show a copyable CI recipe and reviewer checklist;
- external adoption or downstream smoke keeps the policy path live where
  bounded;
- no implementation introduces a broad policy language.

## Acceptance Examples

Acceptable:

```text
uselesskey audit-bundle --path target/uselesskey-webhook --ci --expect-profile webhook
  -> exits 0 when the local audit passes and the manifest profile is webhook
  -> exits non-zero with a stable class when the bundle profile is tls
```

Acceptable:

```text
uselesskey audit-bundle --path target/uselesskey-oidc --ci --policy strict
  -> treats path_escape, missing_manifest, missing_receipt, unexpected_artifact,
     scanner_safe_mismatch, runtime_material_mismatch, and unsupported_profile
     as CI failures
```

Not acceptable:

```text
uselesskey audit-bundle --policy "profile == webhook && scanner_safe > 3"
```

Not acceptable:

```text
uselesskey audit-bundle --policy-url https://example.invalid/policy.rego
```

## Test Mapping

| Requirement | Evidence |
| --- | --- |
| Presets are documented and bounded | `cargo xtask spec-check --strict`; docs review |
| Profile expectation is machine-checkable | CLI tests for `--expect-profile` |
| Strict policy uses stable classes | CLI tests for strict pass/fail behavior |
| Policy docs stay current | `cargo xtask docs-sync --check`; `cargo xtask typos` |
| Installed proof remains separate from repo proof | `cargo xtask claim-report --check-public-claims` in closeout |

## Implementation Mapping

| Surface | Owner |
| --- | --- |
| Policy-pack spec | `docs/specs/USELESSKEY-SPEC-0020-downstream-policy-pack.md` |
| Audit controls | `crates/uselesskey-cli/src/main.rs` |
| Audit control tests | `crates/uselesskey-cli/tests/cli.rs` |
| Downstream policy docs | `docs/how-to/` |
| External smoke, if extended | `xtask/src/external_adoption_smoke.rs` |
| Lane plan | `plans/usability-polish/implementation-plan.md` |

## CI Proof

Spec-only PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation PR:

```bash
cargo test -p uselesskey-cli --all-features audit_bundle
cargo xtask external-adoption-smoke --path .
cargo +nightly xtask pr-lite
git diff --check
```

Closeout PR:

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

## Metrics / Promotion Rule

The downstream policy pack is ready for closeout when:

- the `strict` preset is implemented or explicitly deferred with reason;
- profile expectation can be checked without parsing human text;
- downstream policy docs include a copyable CI command and reviewer checklist;
- audit receipts remain metadata-only;
- the installed CLI policy path does not execute repo-local proof machinery;
- docs continue to state that bundle audit proves local consistency, not
  production security, provider compatibility, scanner-policy bypass approval,
  or release readiness.
