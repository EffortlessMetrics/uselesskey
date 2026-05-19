+++
id = "USELESSKEY-SPEC-0017"
kind = "spec"
title = "Bundle product surface"
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
linked_plan = "plans/real-workflow-closure/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0016",
]
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0017: Bundle Product Surface

## Problem

`uselesskey bundle` is the non-Rust adoption surface. It lets platform, CI, and
review users get deterministic fixture directories without importing the Rust
facade crate.

The current profiles prove that this can work, but future bundle changes need a
single product contract before adding more emitters. Users and downstream CI
should be able to answer:

```text
What did this bundle generate?
Which files are valid cases?
Which files are negative cases?
Which files are scanner-safe?
Which files are runtime material?
Which receipts explain the bundle?
Which claims are explicitly out of scope?
```

This spec defines the bundle manifest and receipt surface. It does not implement
all future bundle emitters.

## Behavior

The installed CLI writes a bundle directory:

```bash
uselesskey bundle --profile oidc --out target/uselesskey-oidc
```

Every bundle directory must contain:

```text
manifest.json
receipts/
```

Profile-specific fixture files live under stable subdirectories when the
profile needs more than one artifact family:

```text
target/uselesskey-oidc/
  manifest.json
  jwks/
    valid.json
    negative-duplicate-kid.json
    negative-missing-kid.json
  tokens/
    valid-rs256.json
    negative-alg-none.json
    negative-bad-audience.json
  receipts/
    materialization.json
    audit-surface.json
    bundle-verification.json
    scanner-safety.json
    negative-coverage.json
```

Future profile or export work may add directories such as `k8s/`, `vault/`, or
additional negative fixture classes only through a spec or task doc that names
the user job, scanner-safety posture, and proof boundary.

### Manifest Contract

`manifest.json` is the bundle's primary product contract. The current schema is
versioned by the `version` field. A later schema may rename this to
`schema_version`, but it must preserve a migration path and update this spec.

The manifest must record:

- schema version;
- profile name;
- deterministic seed or seed identity;
- label or spec identity used to derive artifacts;
- requested output format;
- every file path listed by the bundle;
- every artifact path, kind, format, profile, and description;
- artifact lane metadata;
- scanner-safe classification;
- runtime-material classification, either directly or through a stable derived
  audit rule;
- receipt links.

Artifact paths and receipt paths must be relative to the bundle root. They must
not escape the bundle directory, contain absolute paths, or depend on the
developer's local checkout path.

Artifact lane values are:

| Lane | Meaning |
| --- | --- |
| `scanner-safe` | Artifact is safe to use as scanner-safe fixture metadata or malformed public shape. |
| `runtime` | Artifact is generated runtime test material and should stay under an output directory such as `target/`. |
| `materialized` | Artifact was written to disk by explicit bundle/materialization action. |

The manifest may include multiple lanes for one artifact. A public JWK can be
runtime material and scanner-safe. A webhook request can be runtime material but
not scanner-safe.

### Receipt Contract

Bundles must keep receipts metadata-only. Receipts may list paths, kinds,
failure classes, scanner-safe labels, runtime-material labels, counts, hashes of
metadata, and boundaries. Receipts must not copy raw PEM, DER, token, JWK, JWKS,
webhook body, HMAC key, certificate payload, or generated secret-shaped payload
contents into reviewer packets.

Required receipts:

| Receipt | Purpose |
| --- | --- |
| `receipts/materialization.json` | Records deterministic generation inputs, profile, output format, file list, and artifact metadata. |
| `receipts/audit-surface.json` | Records scanner-safe, runtime-material, lane, and profile metadata for bundle audit. |
| `receipts/bundle-verification.json` | Records local `verify-bundle` consistency checks and profile validation outcome. |
| `receipts/scanner-safety.json` | Records scanner-safe classification for each artifact and explains runtime-material boundaries. |
| `receipts/negative-coverage.json` | Records negative fixture classes present in the bundle and maps them to SPEC-0016 stable IDs. |

These receipts are metadata-only. They are required for bundle profiles but do
not create repo public-claim proof, release evidence, provider compatibility
proof, production security assurance, or scanner-evasion claims.

### Negative Fixture Metadata

When a bundle contains a negative fixture, its metadata should record:

- stable failure class from SPEC-0016;
- artifact path;
- positive or negative role;
- expected downstream parser/verifier failure;
- scanner-safe boolean;
- runtime-material boolean;
- docs or spec reference for the boundary.

Example:

```json
{
  "path": "jwks/negative-duplicate-kid.json",
  "kind": "jwks",
  "role": "negative",
  "failure_class": "jwks_duplicate_kid",
  "expected_failure": "ambiguous key selection",
  "scanner_safe": true,
  "runtime_material": false
}
```

### Product Surface Profiles

The bundle product surface covers existing profiles only:

| Profile | User job |
| --- | --- |
| `scanner-safe` | Generate scanner-safe public or malformed fixture shapes for CI/platform review. |
| `tls` | Generate TLS certificate-chain valid and negative fixtures for verifier tests. |
| `oidc` | Generate JWKS and JWT-shaped valid/negative fixtures for validator tests. |
| `webhook` | Generate deterministic webhook request positives and negatives for HMAC verifier tests. |
| `runtime` | Generate runtime fixture material explicitly under an output directory. |

New profiles or contract packs require their own spec or plan item. They must
not be smuggled into this bundle product-surface spec.

### Verification Surface

The installed CLI verification path is:

```bash
uselesskey verify-bundle --path target/uselesskey-oidc
uselesskey inspect-bundle --path target/uselesskey-oidc
uselesskey audit-bundle --path target/uselesskey-oidc --out target/uselesskey-oidc-audit --ci
```

`verify-bundle` proves local bundle consistency against deterministic profile
generation and manifest shape. `inspect-bundle` gives a quick human summary.
`audit-bundle` writes metadata-only reviewer or CI receipts.

Repo-local proof remains separate:

```bash
cargo xtask claim-proof --all-stable
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
```

Installed bundle verification does not replace repo public-claim proof.

## Non-goals

This spec does not prepare or cut v0.10.0.

This spec does not require a version bump, tag, crates.io publish, GitHub
release, or shipper migration.

This spec does not add a new contract pack, profile, emitter, README badge,
provider compatibility matrix, production security assurance, or scanner
evasion claim.

This spec does not require Kubernetes or Vault export emitters to exist in
`uselesskey bundle`.

This spec does not move `claim-proof`, `verification-pack`, or release evidence
out of repo-local `xtask` commands.

This spec does not permit installed CLI commands to execute claim-ledger command
strings or ambient `cargo xtask` commands.

This spec does not permit raw generated payload copying into audit, review, or
verification packets.

## Required Evidence

Docs-only changes to this spec should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Manifest or receipt implementation changes should run:

```bash
cargo test -p uselesskey-cli --all-features bundle verify_bundle audit_bundle
cargo xtask external-adoption-smoke --path .
cargo xtask no-blob
cargo +nightly xtask pr-lite
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines bundle directory, manifest, artifact, and receipt contracts;
- it names existing bundle profiles and their user jobs;
- it defines current receipts and target receipts before implementation;
- it maps negative fixture metadata to SPEC-0016 stable IDs;
- it separates installed bundle verification from repo public-claim proof;
- it forbids raw generated payloads in reviewer/CI receipts;
- it keeps release prep, new profiles, provider compatibility, production
  security, and scanner-evasion claims out of scope.

This spec is implemented when:

- `manifest.json` records all required artifact and receipt metadata;
- `bundle-verification`, `scanner-safety`, and `negative-coverage` receipts are
  emitted or explicitly deferred with a recorded reason;
- `verify-bundle`, `inspect-bundle`, and `audit-bundle` expose the contract
  without copying raw generated payloads;
- external adoption smoke proves the installed CLI bundle loop for the existing
  profiles.

## Acceptance Examples

Acceptable:

```text
uselesskey bundle --profile oidc --out target/uselesskey-oidc
  -> writes manifest.json
  -> writes jwks/valid.json and taxonomy-backed negative JWKS files
  -> writes metadata-only receipts
  -> verify-bundle and audit-bundle can explain the bundle
```

Acceptable:

```text
receipts/negative-coverage.json records jwks_duplicate_kid for
jwks/negative-duplicate-kid.json without copying the JWKS payload into the
receipt.
```

Not acceptable:

```text
manifest.json lists C:\Users\alice\repo\target\uselesskey-oidc\jwks\valid.json
as an artifact path.
```

Not acceptable:

```text
bundle-audit.json embeds a generated webhook request body or private key
payload.
```

## Test Mapping

CLI tests should cover:

- manifest path containment;
- expected profile file lists;
- receipt presence;
- scanner-safe and runtime-material classification;
- negative fixture failure-class metadata;
- `verify-bundle`, `inspect-bundle`, and `audit-bundle` behavior for bundle
  profiles.

External adoption smoke should cover:

- installed-style bundle generation;
- bundle verification;
- bundle inspection;
- bundle audit;
- metadata-only receipt paths.

No-blob checks should cover:

- fixture examples and docs do not commit generated secret-shaped payloads;
- audit and verification receipts stay metadata-only.

## Implementation Mapping

Implementation owners:

- `crates/uselesskey-cli/src/main.rs` owns bundle generation, manifest
  serialization, installed verification, inspection, audit, and receipt
  rendering.
- `crates/uselesskey-cli/tests/cli.rs` owns installed CLI manifest and receipt
  coverage.
- `xtask/src/bundle_proof.rs` owns repo-local bundle proof.
- `xtask/src/external_adoption_smoke.rs` owns installed-style bundle loop
  smoke evidence.
- `docs/contract-packs/README.md` and `docs/how-to/` own task-first
  explanation of bundle profiles.

## CI Proof

Docs-only PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation PR:

```bash
cargo test -p uselesskey-cli --all-features bundle verify_bundle audit_bundle
cargo xtask external-adoption-smoke --path .
cargo xtask no-blob
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

This spec can move to implemented when:

- every existing bundle profile has stable manifest and receipt coverage;
- negative bundle artifacts use SPEC-0016 failure classes in metadata;
- external adoption smoke proves generate, verify, inspect, and audit for the
  existing profiles;
- receipts remain metadata-only under `cargo xtask no-blob`;
- no installed CLI proof path executes repo-local claim-ledger or release
  evidence commands.
