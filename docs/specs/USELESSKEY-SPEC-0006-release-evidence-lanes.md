+++
id = "USELESSKEY-SPEC-0006"
kind = "spec"
title = "Release evidence lanes"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = []
linked_plan = "plans/spec-system/implementation-plan.md"
support_tier_impact = ["docs/status/PUBLIC_CLAIMS.md"]
policy_impact = ["policy/claim-ledger.toml"]
+++

# USELESSKEY-SPEC-0006: Release Evidence Lanes

## Problem

`uselesskey` has many proof commands. Without lane boundaries, agents can either
under-prove public claims or over-run expensive release checks for a narrow PR.

The repo needs a stable mapping from claim risk to evidence depth:

```text
PRs get fast evidence.
Risk gets targeted depth.
Main gets receipts.
Release gets proof.
```

## Behavior

Evidence is split into four normal lanes plus two release depths.

| Lane | Trigger | Purpose |
| --- | --- | --- |
| PR fast gate | Pull request | Cheap correctness, docs, public-surface, and review evidence. |
| PR targeted heavy | Label, release-risk, impacted evidence, or severe `ripr` gap | Mutation or deeper checks only where justified. |
| Main receipt | Push to `main` | Full repo receipt and badge refresh eligibility. |
| Scheduled/release | Nightly, manual, or release | Fuzz, full mutation, supply-chain, publish proof, and shipped-truth evidence. |
| Patch release | Patch release candidate | State confidence, publish-system smoke, drift checks, and touched-claim proof. |
| Minor release | Minor release candidate | Full public-claim proof for stable README and release-note claims. |

The release-evidence command surfaces are:

```bash
cargo xtask release-evidence --version X --patch --dry-run --summary
cargo xtask release-evidence --version X --dry-run --summary
```

Patch evidence should include cheap state confidence and patch-relevant drift
checks. Minor evidence should include full stable public-claim proof, including
contract-pack proofs.

Release evidence must distinguish:

- repo-local workspace proof;
- external crates.io smoke;
- generated badge endpoint drift;
- docs.rs state;
- release artifact or receipt state.

Queued docs.rs builds are not a republish reason. They should be recorded
honestly as queued, complete, or failed.

## Non-goals

This spec does not publish crates, create tags, or edit releases.

This spec does not require full mutation or every contract-pack proof for every
patch PR.

This spec does not replace the post-release audit checklist.

This spec does not add new proof commands. It defines how existing commands are
classified for PR, main, patch, minor, scheduled, and release lanes.

## Required Evidence

Release-lane planning:

```bash
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
```

Core proof commands mapped by the lanes:

```bash
cargo xtask pr
cargo xtask badges --check
cargo xtask scanner-safe-reference --check
cargo xtask cratesio-smoke --version X
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask publish-check
cargo xtask publish-preflight
```

Docs-only changes to this spec should run:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines PR, main, scheduled, patch, and minor evidence lanes;
- it maps existing proof commands to those lanes;
- it defines patch versus minor release proof depth;
- it keeps external crates.io smoke separate from workspace-local checks;
- it records docs.rs state honestly without treating queue lag as republish
  evidence.

This spec is implemented when:

- release evidence includes `spec-check`;
- patch and minor release evidence clearly show which public claims were proven;
- claim-ledger entries can name the release lanes that carry each claim.

## Acceptance Examples

Patch release candidate:

```bash
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
```

Expected shape:

```text
publish-system checks
badge drift checks
scanner-safe drift checks
external install smoke or planned external install smoke
touched-claim proof
spec-check once available
```

Minor release candidate:

```bash
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
```

Expected shape:

```text
patch lane checks
full public-surface proof
contract-pack proofs
crates.io smoke plan
supply-chain proof
spec-check --strict once available
```

Post-publish smoke:

```bash
cargo xtask cratesio-smoke --version 0.8.0
```

This proves the published-manifest view for that version. It does not prove
future registry state or every downstream feature combination.

## Test Mapping

Lane mapping should be tested at the command and receipt level:

- `cargo xtask pr` covers PR fast gate behavior.
- `cargo xtask impacted-evidence` decides targeted mutation routing.
- `cargo xtask mutants-pr --changed` covers targeted mutation when routed.
- `cargo xtask badges --check` covers generated endpoint drift.
- `cargo xtask scanner-safe-reference --check` covers scanner-safe reference
  evidence.
- `cargo xtask bundle-proof --profile <profile>` covers contract-pack proof.
- `cargo xtask cratesio-smoke --version X` covers external registry smoke.
- `cargo xtask release-evidence --version X ...` writes release evidence
  artifacts and summaries.

## Implementation Mapping

Release evidence lanes are owned by:

- `xtask` release, smoke, bundle-proof, badge, scanner-safe, and PR commands;
- `.github/workflows/` for hosted PR, main, scheduled, and release execution;
- `policy/claim-ledger.toml` for claim to lane mapping;
- `docs/release/post-release-audit.md` for post-publish audit;
- `docs/status/PUBLIC_CLAIMS.md` for reader-facing claim status;
- future `spec-check` wiring for source-of-truth drift.

## CI Proof

Docs-only changes:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Release-evidence tooling changes:

```bash
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask pr
git diff --check
```

After `spec-check` exists:

```bash
cargo xtask spec-check --strict
```

## Metrics / Promotion Rule

This spec remains `accepted` until `spec-check` is wired into release evidence.

It can move to `implemented` when patch and minor release evidence both include
source-of-truth proof and claim-ledger coverage.
