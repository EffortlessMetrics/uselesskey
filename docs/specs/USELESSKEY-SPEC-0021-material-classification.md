+++
id = "USELESSKEY-SPEC-0021"
kind = "spec"
title = "Material classification"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-19"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
]
linked_plan = "plans/real-workflow-closure/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0016",
  "USELESSKEY-SPEC-0017",
]
support_tier_impact = []
policy_impact = [
  "policy/negative-fixtures.toml",
]
+++

# USELESSKEY-SPEC-0021: Material Classification

## Problem

`uselesskey` now exposes the same generated fixture through several product
surfaces: Rust APIs, installed bundle output, audit receipts, external examples,
and task docs. Those surfaces need one operational vocabulary for whether an
artifact is scanner-safe, runtime material, or metadata-only.

Without a shared classification contract, a fixture can be easy to generate but
hard to review:

```text
Is this file safe to commit?
Is it generated runtime material that should stay under target/?
Is this receipt allowed to leave CI?
Does this audit packet contain raw payloads?
```

## Behavior

Every artifact, receipt, and reviewer handoff should use these classifications:

| Classification | Meaning |
| --- | --- |
| `scanner_safe` | The artifact is public material, malformed shape data, or metadata that `uselesskey` intentionally treats as safe for scanner-friendly examples when documented. |
| `runtime_material` | The artifact is generated for tests under an explicit output directory such as `target/`; it should not be committed or copied into reviewer packets unless separately documented scanner-safe. |
| `metadata_only` | The artifact is a receipt, audit packet, schema, status page, or proof summary that may name paths/classes/counts/boundaries but must not copy raw fixture payloads. |

The same file may have more than one lane in a manifest, but the user-facing
classification must stay unambiguous. For example, a public JWK can be generated
at runtime and still be scanner-safe. A webhook request fixture is runtime
material and not scanner-safe. A bundle audit JSON file is metadata-only.

### Required Labels

Bundle manifests, audit receipts, and negative coverage receipts must expose or
derive:

```text
scanner_safe
runtime_material
metadata-only receipt boundary
```

Where a current schema derives `runtime_material` from `scanner_safe`, the docs
must say so explicitly and future schema changes must preserve a migration path.

### Forbidden Metadata-Only Payloads

Metadata-only surfaces must not copy:

- PEM private keys;
- DER private material;
- JWT token values;
- HMAC secrets;
- JWK private members;
- JWK `k` values;
- webhook request bodies;
- Vault or Kubernetes secret payload values;
- generated secret-shaped payloads from runtime bundles.

Metadata-only surfaces may include relative paths, artifact kinds, failure
classes, counts, profile names, command names, schema versions, and boundary
language.

## Non-goals

This spec does not make scanner-safe a production security guarantee.

This spec does not claim scanner evasion or promise that every third-party
scanner will classify every shape the same way.

This spec does not permit committing generated runtime material.

This spec does not move repo-local claim proof into the installed CLI.

This spec does not add a new bundle profile, contract pack, fixture family,
version bump, tag, publish, or release lane.

## Required Evidence

Docs-only changes should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation changes that alter classification should run:

```bash
cargo test -p uselesskey-cli --all-features bundle verify_bundle audit_bundle
cargo xtask external-adoption-smoke --path .
cargo xtask no-blob
cargo +nightly xtask pr-lite
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines scanner-safe, runtime-material, and metadata-only classifications;
- it names forbidden metadata-only payloads;
- it requires bundle/audit surfaces to expose or derive scanner-safe and
  runtime-material labels;
- it preserves existing proof boundaries and non-goals.

This spec is implemented when:

- bundle manifests and audit receipts expose the classification labels required
  by SPEC-0014 and SPEC-0017;
- `audit-bundle` and reviewer docs keep receipts metadata-only;
- task-first docs say whether generated outputs belong under `target/`;
- `cargo xtask no-blob` remains green for docs, examples, and receipts.

## Acceptance Examples

Acceptable metadata-only audit entry:

```json
{
  "path": "requests/negative-missing-signature.json",
  "kind": "webhook",
  "scanner_safe": false,
  "runtime_material": true,
  "failure_class": "webhook_missing_signature"
}
```

Not acceptable:

```text
bundle-audit.json embeds the generated webhook request body, signature header,
or verifier secret.
```

## Test Mapping

Material classification maps to:

- CLI bundle tests for manifest metadata;
- CLI audit tests for receipt metadata;
- `cargo xtask no-blob` for committed docs/examples/fixtures;
- external adoption smoke for installed-user bundle paths;
- docs-sync and typos for copyable docs.

## Implementation Mapping

Owners:

- `crates/uselesskey-cli` owns bundle manifest, audit, inspect, and receipt
  classification display;
- `policy/negative-fixtures.toml` records scanner-safe and runtime-material
  posture for negative classes;
- `docs/reference/bundle-audit-json.md` documents stable audit JSON fields;
- `docs/status/negative-fixture-matrix.md` mirrors negative-class posture for
  readers;
- `docs/how-to/` owns task-specific guidance on what belongs under `target/`.

## CI Proof

Docs-only PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Classification implementation PR:

```bash
cargo test -p uselesskey-cli --all-features bundle verify_bundle audit_bundle
cargo xtask external-adoption-smoke --path .
cargo xtask no-blob
cargo +nightly xtask pr-lite
git diff --check
```

## Metrics / Promotion Rule

This spec can move to implemented when all current bundle profiles expose
scanner-safe/runtime-material posture through manifest and audit surfaces, and
the docs/status matrix names the classification for user-visible negative
classes.
