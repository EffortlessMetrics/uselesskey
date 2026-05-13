+++
id = "USELESSKEY-SPEC-0008"
kind = "spec"
title = "Claim-proof execution"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = ["USELESSKEY-ADR-0002"]
linked_plan = "plans/claim-backed-verification/implementation-plan.md"
support_tier_impact = ["docs/status/PUBLIC_CLAIMS.md"]
policy_impact = ["policy/claim-ledger.toml"]
+++

# USELESSKEY-SPEC-0008: Claim-Proof Execution

## Problem

`cargo xtask claim-report` makes public claims discoverable, but it deliberately
does not run proof commands. Users still need a safe way to prove a selected
claim without manually copying commands from the ledger.

Executing claim proofs is more sensitive than reporting claims because
`policy/claim-ledger.toml` contains reader-facing command strings. Those strings
must not become arbitrary shell input.

## Behavior

`cargo xtask claim-proof` runs proof handlers for selected public claims and
writes per-claim receipts under:

```text
target/claim-proof/<claim>/
```

Required command shapes:

```bash
cargo xtask claim-proof --claim scanner-safe-fixtures
cargo xtask claim-proof --claim tls-contract-pack
cargo xtask claim-proof --all-stable
```

Claim-proof execution must use symbolic, repo-owned handlers. It must not
shell-evaluate arbitrary strings from `policy/claim-ledger.toml`.

Initial handler mapping:

| Claim | Handlers |
| --- | --- |
| `scanner-safe-fixtures` | `scanner_safe_reference_check`, `no_blob`, `badges_check` |
| `ripr-plus-evidence-endpoint` | `badges_check`, `test_efficiency_report` |
| `tls-contract-pack` | `bundle_proof_tls`, `no_blob` |
| `oidc-jwks-contract-pack` | `bundle_proof_oidc`, `no_blob` |
| `public-crate-surface-cleanup` | `public_surface`, `publish_check`, `publish_preflight` |
| `generated-badge-endpoints` | `badges_check` |
| `external-cratesio-install-smoke` | `cratesio_smoke_version` with explicit version only |

`--all-stable` runs stable claims with claim-proof handlers. It must not run
release-proof claims such as `external-cratesio-install-smoke` unless the user
passes an explicit version option in a later command shape.

Each receipt must record:

- claim id;
- status;
- proof handlers run;
- command argv executed by each handler;
- artifacts checked or written;
- boundary;
- exit status;
- timestamp;
- git head.

## Non-goals

This spec does not implement `cargo xtask claim-proof`.

This spec does not add new public claims.

This spec does not allow arbitrary shell execution from TOML command strings.

This spec does not run broad mutation, fuzzing, or full release evidence from
`claim-proof --all-stable`.

This spec does not make crates.io smoke implicit. Registry smoke requires an
explicit version.

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
cargo test -p xtask claim_proof
cargo xtask claim-proof --claim scanner-safe-fixtures
cargo xtask claim-proof --claim tls-contract-pack
cargo xtask claim-proof --all-stable
```

## Acceptance

This spec is accepted when:

- it defines claim-proof as a runner, not a report;
- it requires symbolic handler mappings instead of shell execution from TOML;
- it defines initial supported claims and handlers;
- it defines receipt paths and required receipt fields;
- it excludes implicit crates.io smoke, mutation, fuzzing, and full release
  evidence from default claim-proof runs.

This spec is implemented when:

- `cargo xtask claim-proof --claim scanner-safe-fixtures` writes a passing
  receipt;
- `cargo xtask claim-proof --claim tls-contract-pack` writes a passing receipt;
- `cargo xtask claim-proof --all-stable` runs all stable supported claims;
- unsupported claims fail or report unsupported status explicitly;
- receipts include boundaries and command argv without exposing generated
  secret-shaped payloads.

## Acceptance Examples

Valid handler policy:

```toml
[[claim_proof]]
claim = "scanner-safe-fixtures"
handlers = ["scanner_safe_reference_check", "no_blob", "badges_check"]
```

Invalid handler policy:

```toml
[[claim_proof]]
claim = "scanner-safe-fixtures"
command = "cargo xtask scanner-safe-reference --check && cargo xtask no-blob"
```

The invalid example stores shell text as policy. Claim-proof must use known
handler identifiers and construct command argv in code.

Valid release-proof behavior:

```text
cargo xtask claim-proof --all-stable
```

This does not run crates.io smoke because `external-cratesio-install-smoke` is
not a stable claim and registry proof needs an explicit version.

## Test Mapping

Claim-proof implementation tests must cover:

- handler mapping for `scanner-safe-fixtures`;
- handler mapping for `tls-contract-pack`;
- `--all-stable` selection;
- unknown claim rejection;
- release-proof claim rejection without explicit version;
- receipt JSON and Markdown shape;
- command failures returning claim-local failure receipts.

## Implementation Mapping

Claim-proof execution is owned by:

- `xtask` command parsing for `claim-proof`;
- `policy/claim-ledger.toml` for symbolic handler policy;
- `policy/claim-ledger.toml` claim rows for boundaries and status;
- `target/claim-proof/<claim>/receipt.json` and `.md` for receipts;
- this spec for the execution safety contract.

## CI Proof

Docs-only policy/spec PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation PR:

```bash
cargo test -p xtask claim_proof
cargo xtask claim-proof --claim scanner-safe-fixtures
cargo xtask claim-proof --claim tls-contract-pack
cargo xtask claim-proof --all-stable
cargo xtask pr
git diff --check
```

## Metrics / Promotion Rule

This spec remains `accepted` until `claim-proof` exists and writes receipts for
the initial supported stable claims.

It can move to `implemented` when `claim-proof --all-stable` is stable enough to
be consumed by release evidence or verification-pack without arbitrary command
execution.
