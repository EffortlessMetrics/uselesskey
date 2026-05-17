+++
id = "USELESSKEY-SPEC-0007"
kind = "spec"
title = "PR review evidence"
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

# USELESSKEY-SPEC-0007: PR Review Evidence

## Problem

PR evidence needs to help reviewers and agents answer what changed, what seams
look weakly exposed, which focused test would improve evidence, and whether
targeted mutation should run.

That evidence must not be confused with public README badges. The README
`ripr+` badge is repo-scoped. PR `ripr` review guidance is diff-scoped and
advisory.

## Behavior

PR review evidence is produced under `target/` and consumed by job summaries,
non-blocking annotations, and CI artifacts.

Expected artifacts:

```text
target/ripr/pr/repo-exposure.json
target/ripr/pr/repo-exposure.md
target/ripr/pr/summary.md
target/ripr/review/comments.json
target/ripr/review/comments.md
```

The command surfaces are:

```bash
cargo xtask ripr-pr
cargo xtask ripr-pr --check
cargo xtask ripr-review-comments
cargo xtask ripr-review-comments --check
cargo xtask ripr-pr-summary
cargo xtask ripr-pr-summary --check
```

`ripr` review guidance is routed by field:

| Field | Handling |
| --- | --- |
| `comments[]` | May become non-blocking changed-line warning annotations. |
| `summary_only[]` | GitHub job summary and artifact only. |
| `suppressed[]` | Artifact only. |
| `warnings[]` | Job summary warning section. |

Inline PR comments are disabled by default. Durable review-thread comments are
allowed only by a later explicit opt-in policy.

`--check` commands must validate artifact contracts rather than post anything
to GitHub.

## Non-goals

This spec does not make `ripr` PR evidence blocking by default.

This spec does not post inline PR comments.

This spec does not use PR-scoped `ripr` artifacts as README badge sources.

This spec does not claim runtime mutation adequacy, coverage, or correctness.

This spec does not require targeted mutation unless labels, release-risk,
impacted evidence, or severe `ripr` gaps route it.

## Required Evidence

PR review evidence checks:

```bash
cargo xtask ripr-pr --check
cargo xtask ripr-review-comments --check
cargo xtask ripr-pr-summary --check
```

Docs-only changes to this spec should run:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

When changing CI wiring, run:

```bash
cargo xtask ripr-pr
cargo xtask ripr-review-comments
cargo xtask pr
```

## Acceptance

This spec is accepted when:

- it separates repo-scoped `ripr+` badges from PR-scoped review evidence;
- it defines expected PR evidence artifacts;
- it defines `comments[]`, `summary_only[]`, `suppressed[]`, and `warnings[]`
  handling;
- it keeps inline comments disabled by default;
- it identifies `--check` as artifact-contract validation.

This spec is implemented when:

- CI emits `ripr` PR evidence and review guidance;
- PR summaries are generated from machine-readable PR evidence artifacts;
- `comments[]` can produce non-blocking changed-line annotations;
- artifacts are uploaded for `target/ripr/pr` and `target/ripr/review`;
- `cargo xtask spec-check` can validate the documented contract.

## Acceptance Examples

Valid changed-line annotation source:

```json
{
  "comments": [
    {
      "path": "crates/example/src/lib.rs",
      "line": 42,
      "title": "RIPR",
      "body": "A focused test should assert the changed branch."
    }
  ]
}
```

Invalid annotation source:

```json
{
  "summary_only": [
    {
      "title": "No changed line placement"
    }
  ]
}
```

`summary_only[]` is useful evidence, but it is not safely line-placeable and
must not become a check annotation.

Valid default:

```text
RIPR_COMMENT_MODE=off
```

Any future inline-comment mode must be opt-in, capped, advisory, changed-line
only, and deduplicated.

## Test Mapping

PR review evidence maps to:

- `cargo xtask ripr-pr` for PR-scoped exposure artifacts;
- `cargo xtask ripr-pr --check` for artifact contract validation;
- `cargo xtask ripr-review-comments` for PR-scoped review guidance;
- `cargo xtask ripr-review-comments --check` for review artifact validation;
- `cargo xtask ripr-pr-summary --check` for stable summary contract validation;
- `cargo xtask ripr-annotations` for non-blocking annotations from
  `comments[]`;
- `cargo xtask impacted-evidence` for targeted mutation routing;
- `cargo xtask mutants-pr --changed` when routing requires targeted mutation.

## Implementation Mapping

PR review evidence is owned by:

- `xtask` `ripr-pr`, `ripr-review-comments`, and check commands;
- `.github/workflows/ci.yml` for PR summary, annotations, and artifact upload;
- `docs/VERIFICATION.md` for public explanation of PR evidence boundaries;
- `policy/claim-ledger.toml` for advisory public-claim mapping;
- this spec for the review evidence contract.

## CI Proof

Docs-only changes:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

CI wiring changes:

```bash
cargo xtask ripr-pr
cargo xtask ripr-review-comments
cargo xtask ripr-pr --check
cargo xtask ripr-review-comments --check
cargo xtask ripr-pr-summary --check
cargo xtask pr
```

After `spec-check` exists:

```bash
cargo xtask spec-check
```

## Metrics / Promotion Rule

This spec remains `accepted` while `ripr` evidence is advisory and diff-scoped.

It can move to `implemented` when `spec-check` can validate the source-of-truth
contract and CI continues to emit review summaries, safe annotations, and
artifacts without inline-comment noise.
