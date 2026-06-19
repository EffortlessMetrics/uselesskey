+++
id = "USELESSKEY-HANDOFF-2026-06-19-v0-10-adoption-handoff"
kind = "handoff"
title = "v0.10 adoption handoff import"
status = "implemented"
owner = "EffortlessMetrics"
created = "2026-06-19"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = [
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0017",
  "USELESSKEY-SPEC-0018",
  "USELESSKEY-SPEC-0019",
  "USELESSKEY-SPEC-0020",
]
linked_prs = []
linked_releases = []
+++

# v0.10 Adoption Handoff Import

## Current State

`uselesskey-swarm` has prepared and proven the release-adoption surface for the
v0.10.0 candidate lane. `EffortlessMetrics/uselesskey` remains the source
boundary for the release candidate, publication, tag, and immutable release
record.

This handoff imports the swarm release-adoption packet into the source repo
without changing versions, publishing crates, creating a release candidate,
creating tags, or moving release authority.

Pinned state:

- Source base SHA: `32bb2398c2f31a32d37f03bb0151c4eb88a7c9d5`
- Swarm handoff SHA: `fd00a23f1efb3dd4701c1d15715ea032569fea85`
- Swarm post-merge Source of Truth run: `27848122732`
- Swarm post-merge EM CI Routed Rust run: `27848122731`
- Swarm required result: `Uselesskey Rust Small Result`

Transferred changes in this PR:

- source-repo handoff record only;
- pinned swarm packet paths, source base, proof commands, receipt contract,
  package proof, deferred work, non-claims, and rollback;
- no source code, version, package metadata, changelog, release-note, tag,
  signing, publishing, or release-authority changes.

## Relevant Links

Source specs governing the imported release-adoption surface:

- `docs/specs/USELESSKEY-SPEC-0006-release-evidence-lanes.md`
- `docs/specs/USELESSKEY-SPEC-0013-external-adoption-smoke.md`
- `docs/specs/USELESSKEY-SPEC-0014-installed-bundle-audit.md`
- `docs/specs/USELESSKEY-SPEC-0017-bundle-product-surface.md`
- `docs/specs/USELESSKEY-SPEC-0018-install-distribution-polish.md`
- `docs/specs/USELESSKEY-SPEC-0019-library-facade-polish.md`
- `docs/specs/USELESSKEY-SPEC-0020-downstream-policy-pack.md`

Swarm packet paths pinned at
`fd00a23f1efb3dd4701c1d15715ea032569fea85`:

- `docs/handoffs/2026-06-19-v0-10-release-adoption-closure-closeout.md`
- `docs/learnings/2026-06-v0.10-release-adoption-handoff.md`
- `docs/release/v0.10-source-handoff.md`
- `docs/release/v0.10-adoption-proof-inventory.md`
- `docs/release/v0.10-command-ledger.md`
- `docs/release/v0.10-receipt-contract.md`
- `docs/release/v0.10.0-package-dry-run.md`
- `docs/release/v0.10.0-readiness-record.md`

The older swarm handoff file still names its pre-merge proof-base commit. This
source import intentionally treats the merged swarm SHA above as the handoff
authority.

## Proof Already Run

Swarm post-merge proof at `fd00a23f1efb3dd4701c1d15715ea032569fea85`:

- `Source of Truth Advisory`: passed in run `27848122732`.
- `EM CI Routed Rust`: passed in run `27848122731`.
- `Uselesskey Main Full Gate`: passed in `1h37m49s`.
- `Uselesskey Rust Small Result`: passed.

Swarm release-adoption proof commands recorded by the closeout:

```bash
cargo package --workspace --allow-dirty --exclude uselesskey-bdd --exclude uselesskey-bdd-steps --exclude uselesskey-interop-tests --exclude uselesskey-test-support --exclude uselesskey-test-grid --exclude uselesskey-feature-grid --exclude uselesskey-bench --exclude uselesskey-integration-tests --exclude materialize-shape-buildrs-example --exclude materialize-buildrs-example --exclude xtask
cargo xtask adoption-regression --external
cargo xtask check-doc-artifacts
cargo xtask check-goals
cargo xtask docs-sync --check
cargo xtask external-adoption-smoke --path . --ci-recipes --format json
cargo xtask external-adoption-smoke --path . --library-examples
cargo xtask no-blob
cargo xtask publish-check
cargo xtask publish-preflight
cargo xtask typos
git diff --check
rg "0\.9\.1|0\.10\.0" README.md docs examples crates
```

Source PR 1 proof is intentionally docs-only:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

## Command Ledger

The source release-candidate lane must preserve the swarm command ledger
boundary:

- public install and dependency snippets remain on the current published
  version until the source version-bump or post-publication slice changes them;
- `0.10.0` snippets are release-candidate targets until crates.io publication
  exists;
- release-facing CLI commands must be proved by package or external-adoption
  paths, not by workspace-only shortcuts;
- CI automation must branch on stable machine fields, not Markdown or log prose.

The package-proven source lane must rerun:

```bash
cargo xtask publish-preflight
cargo xtask publish-check
cargo xtask no-blob
cargo xtask check-bundle-schemas
cargo xtask check-audit-receipts
cargo xtask check-adoption-command-ledger
cargo xtask external-adoption-smoke --path . --ci-recipes --format json
cargo xtask external-adoption-smoke --path . --library-examples
cargo xtask adoption-regression --external
cargo test -p uselesskey-cli --all-features audit_bundle
cargo test --workspace --all-features --locked
git diff --check
```

Also inspect package file lists for generated payloads, receipts, locks,
reports, or local build state before treating the candidate as package-clean.

## Receipt Contract

The release-facing bundle audit contract is `bundle-audit.json`. Downstream
automation may branch on:

- `status`;
- `profile`;
- `checks[].failure_class`.

Stable schema-covered fields include:

- `version`;
- `bundle_path`;
- `manifest_path`;
- `manifest_version`;
- `artifact_count`;
- `receipt_count`;
- `scanner_safe_count`;
- `runtime_material_count`;
- `files[]`;
- `artifacts[]`;
- `receipts[]`;
- `missing_files[]`;
- `unexpected_files[]`;
- `checks[].status`;
- `checks[].name`;
- `checks[].failure_class`.

Automation must not branch on:

- `checks[].detail`;
- review prose;
- log text;
- `bundle-audit.md`.

The metadata-only upload set is limited to:

```text
bundle-audit.json
bundle-audit.md
```

Generated fixture payloads, private material, webhook bodies, runtime keys,
target workdirs, package locks, local reports, and smoke state are not release
upload artifacts.

## Package Proof

The swarm package dry run established the expected package boundary but did not
publish anything. The source candidate must rerun package proof from source
state before publication.

Package proof must establish:

- package metadata and dependency graph are coherent;
- package contents include intended docs, schemas, examples, README, and
  license metadata;
- package contents exclude generated runtime payloads, receipts, lock files,
  reports, local target state, and smoke output;
- the candidate remains scanner-safe under `cargo xtask no-blob`;
- package proof is not publish proof, registry proof, tag proof, signing proof,
  or release-readiness by itself.

## Known Blockers

- `release-execution` is blocked until explicit release approval.
- Source versions, internal dependency constraints, `Cargo.lock`, README/task
  docs, install snippets, dependency snippets, `CHANGELOG`, release notes, and
  package metadata have not been updated in this PR.
- The source repo still needs package-path proof from source candidate state.
- Any missing source command named by this handoff is a release-candidate gap to
  fix before the package-proven PR can pass.

## Next Safe Action

Open the source candidate PR:

```text
release: prepare v0.10.0 candidate
```

That PR should update versions, internal dependency constraints, lockfile state
where appropriate, README/task docs, install/dependency snippets, changelog,
release notes, and package metadata. It should not publish, tag, sign, or create
a GitHub release.

## Deferred Work

- PR 2: `release: prepare v0.10.0 candidate`
- PR 3: package-proven adoption proof from package artifacts
- PR 4: immutable v0.10.0 candidate evidence record
- Release execution: blocked until explicit approval

## Non-goals

Swarm has prepared and proven the release-adoption surface.
It has not created a source release candidate, published crates,
tagged v0.10.0, or changed release authority.

This source import also does not:

- publish crates;
- tag `v0.10.0`;
- push tags;
- sign artifacts;
- create or edit a GitHub release;
- claim crates.io publication;
- claim production security;
- claim provider compatibility;
- claim scanner-policy approval;
- claim downstream verifier correctness;
- replace source-repo package proof.

## Rollback

If this import is wrong, revert the source PR that introduced this handoff and
return to the prior source `main` state. If a later source-candidate slice
uncovers a problem before publication, fix it in the candidate PR sequence and
rerun package proof. If a problem is discovered after publication, treat it as
an explicit corrective-release decision.
