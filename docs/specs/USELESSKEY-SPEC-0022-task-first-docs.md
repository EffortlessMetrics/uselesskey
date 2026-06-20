+++
id = "USELESSKEY-SPEC-0022"
kind = "spec"
title = "Task-first workflow docs"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-19"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
]
linked_plan = "plans/real-workflow-closure/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0016",
  "USELESSKEY-SPEC-0017",
  "USELESSKEY-SPEC-0021",
]
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0022: Task-First Workflow Docs

## Problem

`uselesskey` has a large crate graph and a strong proof system. New users should
not need to understand either before solving a test problem. Task docs need a
stable shape so future pages do not drift back into crate-layout tours or
maintainer-only proof machinery.

The first screen should answer:

```text
What are you trying to test?
What do you copy?
What positive case do you get?
What negative case do you get?
How do you verify or audit it?
What does this not prove?
```

## Behavior

User-facing how-tos for fixture adoption must route by job first and use this
shape unless a page has a documented reason to differ:

```text
# I need to <job>

## Copy this
<command or code>

## What you get
<files, values, fixtures, or types>

## Positive path
<valid fixture behavior>

## Negative path
<SPEC-0016 stable class or documented negative behavior>

## Verify
<installed CLI command, cargo test, or repo-local proof where appropriate>

## Audit / receipt
<metadata-only artifact or smoke path>

## What this does not prove
<boundary>
```

Task docs may link to specs, claim ledgers, `xtask`, and release evidence as
deeper references. They must not require a first-time installed user to read
those internals before seeing the copyable command or facade snippet.

Required current task docs include:

| Page | User job |
| --- | --- |
| `docs/how-to/test-oidc-jwks-validation.md` | Test OIDC/JWKS validator positive and negative paths. |
| `docs/how-to/test-jwt-negative-validation.md` | Test JWT/token claim and parser rejection paths. |
| `docs/how-to/materialize-rsa-fixtures-at-build-time.md` | Materialize RSA fixtures explicitly at build/test time. |
| `docs/how-to/verify-a-fixture-bundle.md` | Verify, inspect, and audit an installed CLI bundle. |

Kubernetes and Vault export docs may follow the same shape, but they remain
bounded to existing export behavior and must not imply a bundle profile or
contract pack unless that surface exists.

## Non-goals

This spec does not reorganize the whole documentation tree.

This spec does not add a fixture family, contract pack, provider compatibility
claim, production security claim, scanner-evasion claim, version bump, tag,
publish, or release lane.

This spec does not move repo-local claim-proof, verification-pack, or release
evidence into installed-user docs except as deeper reviewer references.

## Required Evidence

Docs-only changes should run:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Changes to examples, commands, or snippets should also run the narrow adoption
proof:

```bash
cargo xtask external-adoption-smoke --path .
cargo xtask external-adoption-smoke --path . --library-examples
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines the task-first page shape;
- it names the required current how-tos;
- it keeps internal proof machinery behind the user path;
- it requires positive path, negative path, verification, receipt, and boundary
  content for each accepted workflow page.

This spec is implemented when:

- the required how-tos use the task-first shape or record an explicit
  exception;
- each page names the relevant SPEC-0016 negative class when a negative fixture
  is part of the job;
- docs-sync and external adoption smoke cover the copyable commands/snippets
  where practical.

## Acceptance Examples

Acceptable:

```text
The OIDC/JWKS page starts with `uselesskey bundle --profile oidc`, names
`jwks_duplicate_kid`, and shows `verify-bundle`/`audit-bundle` before linking
to repo-local bundle proof.
```

Not acceptable:

```text
The first task page tells a user to understand claim-ledger, active goal files,
and release evidence before showing how to generate the fixture.
```

## Test Mapping

Task-first docs map to:

- `cargo xtask docs-sync --check` for version and snippet drift;
- `cargo xtask external-adoption-smoke --path .` for installed CLI paths;
- `cargo xtask external-adoption-smoke --path . --library-examples` for facade
  examples;
- `cargo xtask typos` for docs hygiene.

## Implementation Mapping

Owners:

- `docs/how-to/` owns task-first workflow pages;
- `README.md` and `docs/how-to/start-here.md` route users into those pages;
- `docs/reference/` owns deeper schemas, matrices, and long-form references;
- `docs/status/` owns compact status tables and current support surfaces;
- `xtask` owns receipt-backed proof that copyable commands remain valid.

## CI Proof

Docs-only PR:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Task-doc command PR:

```bash
cargo xtask external-adoption-smoke --path .
cargo xtask external-adoption-smoke --path . --library-examples
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

## Metrics / Promotion Rule

This spec can move to implemented when the required task docs have a copyable
command or snippet, positive case, negative case, verification command,
metadata-only receipt or smoke path, and explicit "does not prove" boundary.
