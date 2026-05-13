+++
id = "USELESSKEY-SPEC-0010"
kind = "spec"
title = "PR-lite evidence ergonomics"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = []
linked_plan = "plans/pr-lite-evidence/implementation-plan.md"
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0010: PR-Lite Evidence Ergonomics

## Problem

`uselesskey` has strong PR, release, claim, and contract-pack evidence, but the
local path to that evidence can be too coarse for ordinary PR work.

Agents and contributors need a bounded local command that approximates hosted PR
CI closely enough to catch common orchestration and drift failures before a
push. They also need heavy evidence routing to explain itself: why targeted
mutation, fuzz, bundle proof, or deeper release proof ran, skipped, or fell
back.

Without that contract, contributors can overclaim local validation, hosted CI
can spend time on avoidable failures, and targeted mutation can feel surprising
instead of traceable.

## Behavior

`cargo xtask pr-lite` is a local, bounded, high-signal approximation of hosted
PR CI. It is not a release gate and does not replace `cargo xtask pr`.

The command must write receipts:

```text
target/pr-lite/pr-lite.json
target/pr-lite/pr-lite.md
```

The receipts must summarize:

- checks run;
- checks skipped;
- skip reasons;
- heavy evidence routing decisions;
- follow-up commands for hosted-only or intentionally deferred proof.

The initial PR-lite check set should prefer cheap, deterministic checks:

```text
spec-check --strict
docs-sync --check
check-file-policy
no-blob
public-surface
publish-check
impacted-evidence
ripr-pr --check
ripr-review-comments --check
examples-smoke when cheap or touched
BDD/check paths when touched
fuzz build when touched
```

Heavy evidence routing must be receipt-backed. Mutation routing receipts should
show:

```text
changed files
owner crates
public owner surfaces touched
ripr severity
labels considered
release-risk decision
selected mutation command
whether diff-scoped mutation is available
fallback reason when crate-scope mutation is used
```

Diff-scoped mutation may be used only when the tool support and changed-file
mapping are reliable. If diff generation or command support fails, the command
must fall back to the existing crate-scope mutation route and record why.

## Non-goals

This spec does not weaken mutation requirements.

This spec does not make PR-lite equivalent to hosted CI, `cargo xtask pr`, or
release evidence.

This spec does not add new public product claims, fixture profiles, README
badges, release execution, dependency churn, shipper migration work, no-panic
burndown, or TLS mTLS/revocation/CT/browser trust-store behavior.

This spec does not require full mutation, fuzzing, or full release evidence in
PR-lite by default.

## Required Evidence

Docs-only changes to this spec should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

PR-lite implementation changes should run:

```bash
cargo test -p xtask pr_lite
cargo xtask pr-lite
cargo xtask pr-lite --format json
cargo xtask spec-check --strict
cargo xtask pr
git diff --check
```

Mutation-routing changes should run:

```bash
cargo test -p xtask impacted_evidence
cargo xtask impacted-evidence
cargo xtask mutants-pr --changed --explain
cargo xtask pr-lite
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines PR-lite as a bounded local approximation of hosted PR CI;
- it defines Markdown and JSON PR-lite receipts;
- it defines heavy evidence routing receipts;
- it keeps PR-lite separate from full PR, hosted CI, and release proof;
- it states that diff-scoped mutation must fall back without hiding evidence.

This spec is implemented when:

- `cargo xtask pr-lite` emits `target/pr-lite/pr-lite.json` and
  `target/pr-lite/pr-lite.md`;
- PR-lite receipts distinguish run, skipped, failed, and hosted-only proof;
- mutation routing receipts explain targeted mutation decisions;
- diff-scoped mutation is used only where safe and records fallback reasons;
- agent docs explain how to report partial local evidence honestly.

## Acceptance Examples

Valid PR-lite summary:

```text
pr-lite: pass

run:
- spec-check --strict
- docs-sync --check
- no-blob

skipped:
- examples-smoke: no example or adapter paths changed
- fuzz build: no fuzz-owned paths changed

heavy routing:
- targeted mutation: not required
- reason: no public-owner crate changes and no severe ripr gap
```

Valid targeted mutation routing receipt:

```json
{
  "required": true,
  "reason": "public-owner crate changed",
  "changed_files": ["crates/uselesskey-x509/src/chain.rs"],
  "owner_crates": ["uselesskey-x509"],
  "selected_command": "cargo xtask mutants-pr --changed",
  "diff_scoped": {
    "available": false,
    "fallback": "diff mapping not reliable for generated test harness"
  }
}
```

Invalid PR-lite claim:

```text
All gates passed.
```

Use this instead unless full hosted or `cargo xtask pr` proof ran:

```text
Local PR-lite passed; hosted CI and full PR evidence remain separate.
```

## Test Mapping

PR-lite maps to:

- `cargo xtask pr-lite` for local bounded evidence;
- `cargo xtask pr-lite --format json` for machine-readable receipts;
- `cargo xtask spec-check --strict` for source-of-truth drift;
- `cargo xtask docs-sync --check` for docs and generated-snippet drift;
- `cargo xtask check-file-policy` for file-surface policy;
- `cargo xtask no-blob` for scanner-safe fixture policy;
- `cargo xtask public-surface` for public API surface checks;
- `cargo xtask publish-check` for package-shape confidence;
- `cargo xtask impacted-evidence` for changed-path ownership and heavy-routing
  signals;
- `cargo xtask ripr-pr --check` and `cargo xtask ripr-review-comments --check`
  for PR-scoped `ripr` artifact contracts;
- `cargo xtask mutants-pr --changed --explain` for mutation routing receipts.

## Implementation Mapping

PR-lite evidence is owned by:

- `xtask` PR, impacted-evidence, mutation, and receipt code;
- `target/pr-lite/` local receipts;
- `.github/workflows/ci.yml` only where hosted PR summaries need matching
  terminology;
- `docs/handoffs/agent-bootstrap.md` and future local-validation docs for
  agent reporting rules;
- this spec for the behavior contract.

## CI Proof

Docs-only changes:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

PR-lite tooling changes:

```bash
cargo test -p xtask pr_lite
cargo xtask pr-lite
cargo xtask pr-lite --format json
cargo xtask pr
git diff --check
```

Mutation routing changes:

```bash
cargo test -p xtask impacted_evidence
cargo xtask mutants-pr --changed --explain
cargo xtask pr-lite
git diff --check
```

## Metrics / Promotion Rule

This spec remains `accepted` while the lane is implemented.

It can move to `implemented` when PR-lite receipts, heavy-routing receipts,
safe diff-scoped mutation fallback, and local-validation docs are merged and
validated by `cargo xtask spec-check --strict`.
