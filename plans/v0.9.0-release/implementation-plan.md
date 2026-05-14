+++
id = "USELESSKEY-PLAN-0011"
kind = "plan"
title = "v0.9.0 release"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-14"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0004",
  "USELESSKEY-SPEC-0005",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0007",
  "USELESSKEY-SPEC-0008",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0010",
  "USELESSKEY-SPEC-0011",
]
linked_adrs = [
  "USELESSKEY-ADR-0002",
]
+++

# v0.9.0 Release

## Objective

Ship v0.9.0 as the release where `uselesskey`'s public claims are
command-backed, reviewable, locally evidenced, and product-useful.

The release story is:

```text
generated badge endpoints
  -> source-of-truth specs
    -> claim-report / claim-proof
      -> verification-pack
        -> PR-lite evidence
          -> no-panic new-debt cleanup
            -> webhook contract pack
```

## Scope

This lane covers:

- v0.9.0 changelog and release evidence matrix;
- full minor-release proof for the command-backed claim system;
- publish preflight and publish-check proof;
- v0.9.0 publish through `cargo xtask publish`;
- post-release audit for GitHub, crates.io, docs.rs, claim-proof,
  verification-pack, and contract-pack proofs.

## Non-goals

Do not mix these into the v0.9.0 release lane:

- another contract pack before release;
- shipper migration work;
- new README badges;
- TLS mTLS, revocation, CT, or browser trust-store expansion;
- historical no-panic baseline burndown;
- dependency churn;
- broad compatibility-shim churn.

## PR Sequence

1. `release: prepare v0.9.0 changelog and evidence matrix`
   - Update `CHANGELOG.md`.
   - Add `docs/release/evidence-matrix-v0.9.0.md`.
   - Open this active release goal and plan.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask claim-report --check-public-claims
     cargo xtask contract-packs --check
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

2. `release: prove v0.9.0 candidate`
   - Run full minor-release proof.
   - Do not commit generated `target/` receipts unless a tracked receipt path is
     explicitly added.
   - Validation:

     ```bash
     cargo xtask release-evidence --version 0.9.0 --dry-run --summary
     cargo xtask claim-proof --all-stable
     cargo xtask verification-pack --out target/uselesskey-verification
     cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
     cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
     cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
     cargo xtask pr-lite
     cargo xtask pr
     git diff --check
     ```

3. `release: cut v0.9.0`
   - Re-run pre-tag proof.
   - Publish through `cargo xtask publish`.
   - Do not switch to shipper for this release.
   - Validation:

     ```bash
     cargo xtask release-evidence --version 0.9.0 --dry-run --summary
     cargo xtask publish-preflight
     cargo xtask publish-check
     cargo xtask no-blob
     cargo xtask check-no-panic-family
     cargo xtask badges --check
     cargo xtask docs-sync --check
     cargo xtask pr
     git diff --check
     ```

4. `release(v0.9.0): post-release audit record`
   - Verify GitHub release visibility.
   - Verify intended public crates on crates.io.
   - Verify removed shims were not republished.
   - Run `cargo xtask cratesio-smoke --version 0.9.0`.
   - Record docs.rs state honestly. Queued docs.rs builds are not a republish
     reason; failed builds require build-log inspection.
   - Re-run claim-proof, verification-pack, and TLS/OIDC/webhook bundle proofs.

## Proof Commands

Release setup:

```bash
cargo xtask spec-check --strict
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Release candidate:

```bash
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask claim-proof --all-stable
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

Pre-publish:

```bash
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask publish-preflight
cargo xtask publish-check
cargo xtask no-blob
cargo xtask check-no-panic-family
cargo xtask badges --check
cargo xtask docs-sync --check
cargo xtask pr
git diff --check
```

## Rollback

Before tagging or publishing, this lane is ordinary release-candidate work:
revert the release PR or split the failed proof into a fix PR.

After publishing starts, use the existing publish-recovery and post-release
audit docs. Do not rewrite tags, yank crates, or republish without an explicit
operator decision and a written recovery record.

## Stop Conditions

Pause before irreversible release actions if:

- a proof command fails and the failure is not understood;
- `cargo xtask publish-check` or `publish-preflight` fails;
- `no-blob` or scanner-safe proof fails;
- generated badge endpoints drift without explanation;
- docs.rs returns failed build logs instead of queue lag;
- a request asks to switch to shipper for this release;
- the release scope expands into a new contract pack, TLS expansion, dependency
  churn, or historical no-panic baseline work.
