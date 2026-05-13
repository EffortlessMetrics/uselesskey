+++
id = "USELESSKEY-SPEC-0004"
kind = "spec"
title = "Generated evidence endpoints"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = ["USELESSKEY-ADR-0002"]
linked_plan = "plans/spec-system/implementation-plan.md"
support_tier_impact = ["docs/status/PUBLIC_CLAIMS.md"]
policy_impact = ["policy/claim-ledger.toml"]
+++

# USELESSKEY-SPEC-0004: Generated Evidence Endpoints

## Problem

README badges are useful only when they expose real repo-owned evidence. A
badge that is hand-written or copied from another repo becomes a slogan instead
of a public receipt.

`uselesskey` now exposes generated Shields endpoint JSON for `ripr+` and
scanner-safe fixtures. This spec defines the contract for those endpoint files
so the badge row stays small, stable, repo-scoped, and command-backed.

## Behavior

Public badge endpoints live under `badges/` as generated Shields endpoint JSON.
The committed public endpoint files are:

```text
badges/ripr-plus.json
badges/scanner-safe.json
```

Each endpoint must use the minimal Shields shape:

```json
{
  "schemaVersion": 1,
  "label": "ripr+",
  "message": "0",
  "color": "brightgreen"
}
```

`cargo xtask badges` must:

- anchor paths at the workspace root;
- refresh repo-scoped `ripr+` evidence;
- refresh scanner-safe fixture status;
- write public endpoint JSON under `badges/`;
- write detailed reports under `target/`;
- validate Shields endpoint shape before writing committed JSON;
- support `RIPR_BIN` for local or CI pinning.

`cargo xtask badges --check` must:

- regenerate endpoints into `target/xtask/badges/`;
- compare generated endpoint files to committed `badges/*.json`;
- fail when committed endpoints drift;
- avoid mutating committed endpoint files.

If scanner-safe generation fails, the command may write a red debug endpoint
under `target/xtask/badges/scanner-safe.json`, but it must fail before
overwriting committed `badges/scanner-safe.json`.

README badge scope is fixed:

- `ripr+` is repo-scoped public static evidence.
- scanner-safe is repo-scoped fixture-policy evidence.
- PR-scoped `ripr` review guidance is not a README badge source.

## Non-goals

This spec does not add new badge endpoints.

This spec does not make badge counts a complete proof of correctness, coverage,
mutation adequacy, production crypto safety, or scanner evasion.

This spec does not publish target-only reports, full `ripr` reports, or PR
artifacts as README badge data.

This spec does not require bot-driven badge refreshes before endpoint behavior
has settled.

## Required Evidence

Endpoint drift proof:

```bash
cargo xtask badges --check
```

Badge shape tests:

```bash
cargo test -p xtask badge
```

Docs and claim mapping:

```bash
cargo xtask docs-sync --check
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines committed badge endpoint ownership;
- it defines the Shields JSON shape;
- it separates repo-scoped badges from PR-scoped evidence;
- it defines scanner-safe failure behavior;
- it names the proof commands for endpoint drift and shape.

This spec is implemented by the existing badge command when:

- `cargo xtask badges --check` passes;
- `cargo test -p xtask badge` passes;
- README badges point at the committed endpoint paths under `badges/`.

## Acceptance Examples

Valid `ripr+` endpoint:

```json
{
  "schemaVersion": 1,
  "label": "ripr+",
  "message": "511",
  "color": "red"
}
```

Valid scanner-safe endpoint:

```json
{
  "schemaVersion": 1,
  "label": "fixtures",
  "message": "scanner-safe",
  "color": "brightgreen"
}
```

Target-only scanner-safe failure debug endpoint:

```json
{
  "schemaVersion": 1,
  "label": "fixtures",
  "message": "blob-risk",
  "color": "red"
}
```

Invalid public badge source:

```text
target/ripr/review/comments.json
```

That file is PR-scoped review guidance and must stay in summaries or artifacts.

## Test Mapping

Generated endpoint behavior maps to:

- `cargo xtask badges` for refreshing committed public endpoint JSON;
- `cargo xtask badges --check` for drift detection;
- `cargo test -p xtask badge` for endpoint shape and command behavior tests;
- `cargo xtask test-efficiency-report` for the repo-scoped test-efficiency
  report consumed by `ripr+`;
- `cargo xtask scanner-safe-reference --check` and `cargo xtask no-blob` for
  scanner-safe fixture-policy evidence.

## Implementation Mapping

Endpoint generation is owned by:

- `README.md` for the public masthead links;
- `badges/` for committed Shields endpoint JSON;
- `badges/README.md` for regeneration instructions;
- `xtask` for endpoint generation and drift checks;
- `docs/VERIFICATION.md` for badge meanings and limits;
- `docs/reference/verification-badges.md` for detailed badge policy;
- `policy/claim-ledger.toml` for public claim mapping.

## CI Proof

Badge endpoint PRs should run:

```bash
cargo xtask badges --check
cargo test -p xtask badge
cargo xtask docs-sync --check
git diff --check
```

Scanner-safe or fixture-policy changes should also run:

```bash
cargo xtask scanner-safe-reference --check
cargo xtask no-blob
```

## Metrics / Promotion Rule

Optional future endpoints may be added only after their evidence is stable and
generated:

```text
feature-matrix.json
cratesio-smoke.json
supply-chain.json
```

They should remain absent until the proof command, artifact ownership, README
boundary, and claim-ledger entry are in place.
