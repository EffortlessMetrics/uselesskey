+++
id = "USELESSKEY-SPEC-0002"
kind = "spec"
title = "Public claim ledger"
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

# USELESSKEY-SPEC-0002: Public Claim Ledger

## Problem

`uselesskey` public claims need to be easy to audit. The README can say
`scanner-safe fixtures`, `ripr+`, TLS contract pack, OIDC/JWKS contract pack,
or crates.io smoke, but users should not have to infer which command proves
each claim.

A public claim ledger gives the repo a compact source of truth:

```text
claim -> surfaces -> proof commands -> artifacts -> docs -> release lane -> boundary
```

That keeps badge and README language small while preserving enough proof mapping
for maintainers, users, release operators, and agents.

## Behavior

Public claims must be represented in `policy/claim-ledger.toml` when they are
used by README badges, top-level docs, release notes, or release evidence.

Each claim entry must identify:

- a stable `id`;
- `status`;
- public `surfaces`;
- at least one `proof_command`;
- generated `artifacts` or receipts, when applicable;
- user-facing `docs`;
- applicable `release_lanes`;
- an explicit `boundary`.

Initial claim statuses are:

| Status | Meaning |
| --- | --- |
| `stable` | User-facing claim that should be proven in normal PR, docs, or release evidence when touched. |
| `release-proof` | Claim whose primary proof is an external or shipped-state release lane. |
| `advisory` | Reviewer or agent evidence that informs work but does not make a user-facing guarantee by itself. |

The human index in `docs/status/PUBLIC_CLAIMS.md` must summarize the same
claims without replacing the TOML ledger. The Markdown page is for readers; the
TOML file is the future parser target for `cargo xtask spec-check`.

The ledger is allowed to reference commands that already exist but are too
expensive for every PR. It must still name the lane where the command belongs.
For example, `cargo xtask cratesio-smoke --version 0.8.0` is a release-proof
claim, not a cheap PR check.

## Non-goals

This spec does not make every claim blocking in every PR.

This spec does not add new fixture profiles, new badge endpoints, or new
release commands.

This spec does not claim `policy/claim-ledger.toml` is enforced yet. Enforcement
belongs to the future `cargo xtask spec-check` command.

This spec does not turn advisory `ripr` PR evidence into a public product
guarantee.

## Required Evidence

Current docs and generated endpoint checks:

```bash
cargo xtask badges --check
cargo xtask scanner-safe-reference --check
cargo xtask docs-sync --check
git diff --check
```

When validating release-facing claims, use the claim-specific commands recorded
in `policy/claim-ledger.toml`, such as:

```bash
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask cratesio-smoke --version 0.8.0
```

When `spec-check` exists, it must validate that every ledger entry has at least
one proof command and a non-empty boundary.

## Acceptance

This spec is accepted when:

- it defines the required fields for public claim entries;
- `policy/claim-ledger.toml` seeds the current public claims;
- `docs/status/PUBLIC_CLAIMS.md` gives readers a compact index;
- claim boundaries separate fixture safety from production security.

This spec is implemented when:

- `cargo xtask spec-check` parses and validates `policy/claim-ledger.toml`;
- release evidence can report claim-ledger coverage;
- README claims all map to ledger entries or explicitly explain why no ledger
  entry is needed.

## Acceptance Examples

Example: scanner-safe fixtures.

```toml
[[claim]]
id = "scanner-safe-fixtures"
status = "stable"
proof_commands = [
  "cargo xtask scanner-safe-reference --check",
  "cargo xtask no-blob",
  "cargo xtask badges --check",
]
boundary = "Scanner-safe fixture material does not mean every encoded export is safe to commit."
```

Example: PR review evidence.

```toml
[[claim]]
id = "ripr-pr-review-evidence"
status = "advisory"
proof_commands = [
  "cargo xtask ripr-pr --check",
  "cargo xtask ripr-review-comments --check",
]
boundary = "PR evidence is diff-scoped and advisory; it is not the repo-scoped README ripr+ badge."
```

## Test Mapping

Docs-only validation for this spec:

```bash
cargo xtask badges --check
cargo xtask scanner-safe-reference --check
cargo xtask docs-sync --check
git diff --check
```

Future `spec-check` tests must cover:

- all claim IDs are unique;
- `status` is one of `stable`, `release-proof`, or `advisory`;
- `proof_commands` is non-empty;
- `boundary` is non-empty;
- referenced specs and docs exist when listed.

## Implementation Mapping

The claim ledger is owned by:

- `policy/claim-ledger.toml` for machine-readable claim mapping;
- `docs/status/PUBLIC_CLAIMS.md` for human-readable claim status;
- `docs/status/README.md` for status-surface navigation;
- `docs/specs/USELESSKEY-SPEC-0002-public-claim-ledger.md` for the behavior
  contract;
- future `xtask spec-check` code for enforcement.

## CI Proof

Before `spec-check` exists, claim-ledger PRs should run:

```bash
cargo xtask badges --check
cargo xtask scanner-safe-reference --check
cargo xtask docs-sync --check
git diff --check
```

Release operators should run the claim-specific proof commands named in the
ledger for the claims touched by a release.

After `spec-check` exists, claim-ledger PRs should also run:

```bash
cargo xtask spec-check
cargo xtask spec-check --format json
```

## Metrics / Promotion Rule

This spec remains `accepted` until `spec-check` validates the claim ledger.

It can move to `implemented` when all README badge and public promise claims are
represented in the ledger and release evidence reports ledger coverage.
