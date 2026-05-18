+++
id = "USELESSKEY-SPEC-0014"
kind = "spec"
title = "Installed bundle audit"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
]
linked_plan = "plans/installed-bundle-audit/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0012",
  "USELESSKEY-SPEC-0013",
]
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0014: Installed Bundle Audit

## Problem

The v0.10.0 external-adoption lane made installed-style bundle generation,
verification, inspection, and clean-project examples work from outside the repo.
That answers whether a user can start.

The remaining installed-user gap is reviewer handoff. A user can generate a
bundle, but a platform reviewer should not have to clone the repo or learn
`cargo xtask` to answer basic questions:

```text
Which files were generated?
Which files are scanner-safe?
Which files are runtime material?
Are the manifest and receipts internally consistent?
What does this bundle audit explicitly not prove?
```

The installed CLI needs a metadata-only audit command that explains the local
bundle it generated without becoming repo public-claim proof, release evidence,
or a provider compatibility claim.

## Behavior

The installed CLI provides bundle-local audit receipts:

```bash
uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit
uselesskey audit-bundle --path target/uselesskey-webhook --format json
```

When `--out <dir>` is provided, the command writes:

```text
<dir>/bundle-audit.json
<dir>/bundle-audit.md
```

When `--out` is omitted, the command emits Markdown by default and emits JSON
when `--format json` is selected.

The audit receipt is metadata-only. It may include:

- bundle path;
- profile;
- manifest schema/version;
- artifact paths, kinds, formats, descriptions, and scanner-safe labels;
- runtime-material classification derived from manifest metadata;
- receipt records;
- profile-neutral check results;
- profile-specific validation result;
- missing or unexpected file lists;
- stable failure class names;
- boundary and "does not prove" text.

The audit receipt must not include generated PEM, DER, token, JWK, JWKS,
webhook request body, HMAC key, certificate payload, or other raw fixture
payload contents.

Profile-neutral checks cover:

- `manifest.json` exists and parses;
- manifest paths are relative and contained by the bundle path;
- listed artifacts exist;
- bundle content verifies against the manifest and deterministic profile;
- materialization and audit-surface receipts exist;
- audit-surface scanner-safe/runtime-material counts match manifest metadata;
- no unexpected files are present in the bundle tree.

Profile-specific checks are bounded to existing profiles:

| Profile | Audit check |
| --- | --- |
| `scanner-safe` | Scanner-safe/reference artifacts and receipts match the generated manifest. |
| `tls` | Expected TLS valid and negative fixture files, evidence, and receipts match the generated manifest. |
| `oidc` | Expected JWKS/token positive and negative fixture files and receipts match the generated manifest. |
| `webhook` | Expected valid/tampered/wrong-secret/stale/missing/malformed request files, evidence, and receipts match the generated manifest. |
| `runtime` | Runtime fixture files and scanner-safe/runtime-material labels match the generated manifest. |

The command uses stable failure classes:

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

`cargo xtask external-adoption-smoke --path .` must exercise
`audit-bundle` for the installed-style scanner-safe, TLS, OIDC, and webhook
bundle paths.

## Non-goals

This spec does not prepare or cut v0.10.0.

This spec does not require a version bump, tag, crates.io publish, GitHub
release, or shipper migration.

This spec does not add a new public claim, contract pack, README badge, fixture
family, provider compatibility matrix, or production security assurance.

This spec does not move `claim-proof`, `verification-pack`, or release evidence
out of repo-local `xtask` commands.

This spec does not permit installed CLI audit commands to shell out to ambient
`cargo xtask` commands or execute claim-ledger strings.

This spec does not permit copying raw generated fixture payloads into audit
packets.

## Required Evidence

Docs-only changes to this spec should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

The command implementation should run:

```bash
cargo test -p uselesskey-cli --all-features audit_bundle
cargo run -p uselesskey-cli -- bundle --profile webhook --out target/audit-test/webhook
cargo run -p uselesskey-cli -- audit-bundle --path target/audit-test/webhook --out target/audit-test/webhook-audit
cargo run -p uselesskey-cli -- audit-bundle --path target/audit-test/webhook --format json
cargo xtask no-blob
cargo xtask pr-lite
git diff --check
```

External-adoption integration should run:

```bash
cargo test -p xtask external_adoption_smoke
cargo xtask external-adoption-smoke --path .
cargo xtask external-adoption-smoke --path . --format json
cargo xtask adoption-regression --external
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines `uselesskey audit-bundle`;
- it defines Markdown and JSON audit receipt outputs;
- it requires metadata-only audit receipts;
- it defines profile-neutral and profile-specific bundle checks;
- it names stable failure classes;
- it keeps installed audit separate from repo-local claim proof and release
  evidence;
- it preserves provider-compatibility and production-security boundaries;
- it wires audit into clean-project external-adoption smoke.

## Acceptance Examples

Acceptable:

```text
uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit
  -> writes bundle-audit.json and bundle-audit.md
  -> lists request fixture paths, scanner-safe labels, runtime-material counts, and boundaries
  -> does not copy request payloads into the audit directory
```

Acceptable:

```text
uselesskey audit-bundle --path target/uselesskey-tls --format json
  -> emits metadata and check status for the local TLS bundle
  -> says production PKI and mTLS are not proven
```

Not acceptable:

```text
uselesskey audit-bundle
  -> runs cargo xtask claim-proof
```

Not acceptable:

```text
uselesskey audit-bundle
  -> copies generated PEM, token, HMAC, or webhook payload files into the audit packet
```

## Test Mapping

CLI tests cover:

- writing metadata-only JSON and Markdown audit receipts;
- JSON stdout mode;
- scanner-safe and webhook profile audit summaries;
- unexpected file failure;
- absence of raw private key/token-shaped payloads in audit output.

External-adoption smoke tests cover:

- installed-style `audit-bundle` execution for generated bundle profiles;
- audit output paths appearing in the external-adoption receipt.

## Implementation Mapping

Implementation owners:

- `crates/uselesskey-cli/src/main.rs` owns `audit-bundle`, receipt models,
  bundle-local validation, and Markdown/JSON rendering.
- `crates/uselesskey-cli/tests/cli.rs` owns installed CLI audit coverage.
- `xtask/src/external_adoption_smoke.rs` owns clean-project audit execution
  and receipt wiring.
- `docs/how-to/share-installed-bundle-audit.md` owns reviewer handoff
  guidance.

## CI Proof

The closeout evidence should include:

```bash
cargo xtask external-adoption-smoke --path .
cargo xtask adoption-regression --external
cargo xtask docs-sync --check
cargo xtask typos
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

## Metrics / Promotion Rule

The installed bundle audit path is ready for release-prep consideration when:

- external-adoption smoke includes audit receipts for scanner-safe, TLS, OIDC,
  and webhook installed-style bundle paths;
- audit receipts stay metadata-only;
- reviewer handoff docs explain when to use installed `audit-bundle` versus
  repo-local `verification-pack`;
- no public claim or release evidence lane depends on installed audit as a
  substitute for `cargo xtask claim-proof`.
