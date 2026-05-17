+++
id = "USELESSKEY-PLAN-0016"
kind = "plan"
title = "v0.9.1 release"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-17"
milestone = "v0.9.1"
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
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0004",
]
+++

# v0.9.1 Release

## Objective

Ship v0.9.1 as a narrow adoption-confidence patch.

The release story is:

```text
v0.9.0 adoption path
  -> scanner-safe runtime JWK/JWKS metadata correction
    -> adoption-regression receipt
      -> fixture-confidence coverage
        -> no-panic new-debt restoration
          -> patch release audit
```

## Scope

This lane covers:

- v0.9.1 changelog and patch evidence matrix;
- patch release proof for the adoption-confidence surface;
- publish preflight and publish-check proof;
- v0.9.1 publish through `cargo xtask publish`;
- post-release audit for GitHub, crates.io, docs.rs, adoption-regression,
  claim-proof, verification-pack, and contract-pack proofs.

## Non-goals

Do not mix these into the v0.9.1 release lane:

- new contract packs;
- new README badges;
- provider compatibility claims;
- production security claims;
- shipper migration work;
- TLS mTLS, revocation, CT, or browser trust-store expansion;
- historical no-panic baseline burndown;
- broad dependency churn;
- broad SRP refactors.

## PR Sequence

1. `release: prepare v0.9.1`
   - Update `CHANGELOG.md`.
   - Add `docs/release/evidence-matrix-v0.9.1.md`.
   - Open this active release goal and plan.
   - Verify current user-facing version snippets do not leave stale v0.7/v0.8
     copyable install guidance outside historical migration docs.
   - Validation:

     ```bash
     cargo xtask spec-check --strict
     cargo xtask claim-report --check-public-claims
     cargo xtask contract-packs --check
     cargo xtask docs-sync --check
     cargo xtask typos
     git diff --check
     ```

2. `release: prove v0.9.1 candidate`
   - Run patch-release proof.
   - Do not commit generated `target/` receipts unless a tracked receipt path is
     explicitly added.
   - Validation:

     ```bash
     cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary
     cargo xtask adoption-regression
     cargo xtask adoption-regression --format json
     cargo xtask claim-proof --all-stable
     cargo xtask user-path-smoke
     cargo xtask check-no-panic-family
     cargo xtask claim-report --check-public-claims
     cargo xtask contract-packs --check
     cargo +nightly xtask pr-lite
     cargo xtask pr
     git diff --check
     ```

3. `release: cut v0.9.1`
   - Bump publishable crate versions where required.
   - Re-run pre-tag proof.
   - Publish through `cargo xtask publish`.
   - Do not switch to shipper for this release.
   - Validation:

     ```bash
     cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary
     cargo xtask publish-preflight
     cargo xtask publish-check
     cargo xtask no-blob
     cargo xtask check-no-panic-family
     cargo xtask badges --check
     cargo xtask docs-sync --check
     cargo xtask pr
     git diff --check
     ```

4. `release(v0.9.1): post-release audit record`
   - Verify GitHub release visibility.
   - Verify intended public crates on crates.io.
   - Verify removed shims were not republished.
   - Run `cargo xtask cratesio-smoke --version 0.9.1`.
   - Record docs.rs state honestly. Queued docs.rs builds are not a republish
     reason; failed builds require build-log inspection.
   - Re-run adoption-regression, claim-proof, verification-pack, and
     TLS/OIDC/webhook bundle proofs.

5. `docs: close out v0.9.1 release lane`
   - Archive the active goal.
   - Add release closeout and learning records.
   - Leave the repo ready for the next product lane.

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
cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary
cargo xtask adoption-regression
cargo xtask adoption-regression --format json
cargo xtask claim-proof --all-stable
cargo xtask user-path-smoke
cargo xtask check-no-panic-family
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo +nightly xtask pr-lite
cargo xtask pr
git diff --check
```

Pre-publish:

```bash
cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary
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
- the release scope expands into a new contract pack, badge, TLS expansion,
  dependency churn, or historical no-panic baseline work.
