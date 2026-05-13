+++
id = "USELESSKEY-SPEC-0009"
kind = "spec"
title = "Verification-pack receipt bundle"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = ["USELESSKEY-ADR-0002"]
linked_plan = "plans/claim-backed-verification/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0004",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0008",
]
support_tier_impact = ["docs/status/PUBLIC_CLAIMS.md"]
policy_impact = [
  "policy/claim-ledger.toml",
  "policy/contract-packs.toml",
]
+++

# USELESSKEY-SPEC-0009: Verification-Pack Receipt Bundle

## Problem

`uselesskey` now has claim reports, contract-pack checks, badge endpoint checks,
claim-proof receipts, and release evidence. Those receipts are useful, but a
reviewer still has to know which files to collect.

A platform or security team needs one review bundle that answers:

```text
what is claimed
what was checked
what receipts were produced
what boundaries still apply
what generated payloads were intentionally excluded
```

## Behavior

`cargo xtask verification-pack` produces a review bundle under a caller-chosen
output directory:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask verification-pack --out target/uselesskey-verification --claim scanner-safe-fixtures
```

The default bundle contains stable public-claim receipts. A claim-filtered
bundle contains the selected claim plus shared index files needed to understand
that claim.

The bundle layout is:

```text
target/uselesskey-verification/
  README.md
  public-claims.json
  public-claims.md
  contract-packs.json
  contract-packs.md
  badges/
    ripr-plus.json
    scanner-safe.json
  claim-proof/
    scanner-safe-fixtures/
      receipt.json
      receipt.md
    tls-contract-pack/
      receipt.json
      receipt.md
```

The bundle must contain receipts and metadata only. It must not copy generated
secret-shaped payloads, bundle material, private-key text, PEM fixtures, DER
fixtures, JWT-shaped payloads, or Kubernetes/Vault export payloads.

`README.md` in the bundle must explain:

- the commit or git head used to generate the bundle;
- the commands used to generate included receipts;
- which claims are included;
- where each receipt came from;
- the claim boundaries that still apply;
- that badges are front-panel markers, not complete proof.

## Non-goals

This spec does not implement `cargo xtask verification-pack`.

This spec does not define an archive, zip, signing, attestation, SBOM, or
provenance format.

This spec does not upload verification packs to CI artifacts or releases.

This spec does not add new public claims or new README badges.

This spec does not include generated fixture payloads in the pack.

## Required Evidence

Docs-only changes to this spec should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

The implementation PR must add and run:

```bash
cargo test -p xtask verification_pack
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask no-blob
cargo xtask check-file-policy
```

## Acceptance

This spec is accepted when:

- it defines the verification-pack purpose and bundle layout;
- it defines metadata-only bundle contents;
- it names claim-report, contract-pack, badge, and claim-proof receipts as the
  initial inputs;
- it excludes generated fixture payloads and archive/signing formats;
- it defines the implementation proof commands.

This spec is implemented when:

- `cargo xtask verification-pack --out target/uselesskey-verification` writes
  the layout defined here;
- `--claim <id>` writes a filtered pack for a supported claim;
- the pack includes claim boundaries next to included receipts;
- the pack omits generated fixture payloads;
- `cargo xtask no-blob` and `cargo xtask check-file-policy` pass after pack
  generation.

## Acceptance Examples

Valid default pack:

```text
target/uselesskey-verification/public-claims.md
target/uselesskey-verification/contract-packs.json
target/uselesskey-verification/badges/scanner-safe.json
target/uselesskey-verification/claim-proof/scanner-safe-fixtures/receipt.md
target/uselesskey-verification/README.md
```

Invalid pack contents:

```text
target/uselesskey-verification/certs/valid-leaf.pem
target/uselesskey-verification/k8s-secret.yaml
target/uselesskey-verification/private-key.pkcs8.pem
```

Those files are generated fixture material or secret-shaped payload exports.
They belong under local proof output directories, not in a shareable review
pack.

## Test Mapping

Verification-pack implementation tests must cover:

- default bundle layout;
- claim-filtered bundle layout;
- missing receipt failures;
- badge endpoint copying;
- claim boundary rendering;
- exclusion of generated fixture payload paths;
- `README.md` shape and commands section.

## Implementation Mapping

Verification-pack is owned by:

- `xtask` command parsing for `verification-pack`;
- `target/claim-report/` for public-claim report receipts;
- `target/contract-packs/` for contract-pack registry receipts;
- `badges/*.json` for public badge endpoint JSON;
- `target/claim-proof/<claim>/` for claim-proof receipts;
- this spec for the bundle contents and exclusion contract.

## CI Proof

Docs-only spec PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation PR:

```bash
cargo test -p xtask verification_pack
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask no-blob
cargo xtask check-file-policy
cargo xtask pr
git diff --check
```

## Metrics / Promotion Rule

This spec remains `accepted` until the command exists and writes a metadata-only
pack that can be consumed by release evidence.

It can move to `implemented` when release evidence can include a
verification-pack summary without adding generated secret-shaped payloads to
artifacts.
