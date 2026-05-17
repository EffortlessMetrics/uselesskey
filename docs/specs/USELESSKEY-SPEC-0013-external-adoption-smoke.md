+++
id = "USELESSKEY-SPEC-0013"
kind = "spec"
title = "External adoption smoke"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-17"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
]
linked_plan = "plans/v0.10.0-external-adoption/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0006",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0012",
]
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0013: External Adoption Smoke

## Problem

`uselesskey` now has strong repo-local proof: claim reports, claim-proof,
verification packs, adoption-regression receipts, PR-lite, and release-evidence
lanes. Those prove the repository, but a new user experiences the product from
outside the repo:

```text
cargo install uselesskey-cli
uselesskey bundle --profile webhook --out target/uselesskey-webhook
cargo test
```

The repo needs a clean-project adoption proof that exercises the documented user
paths without relying on hidden workspace state, checked-out examples, or
maintainer-only `xtask` knowledge.

Without that proof, docs can drift into commands that work only in this
workspace, the installed CLI can feel secondary to repo automation, and
reviewers cannot tell which adoption paths were actually checked.

## Behavior

`cargo xtask external-adoption-smoke` proves that `uselesskey` can be adopted
from clean projects and installed-style CLI workflows.

The primary buildout mode is local path mode:

```bash
cargo xtask external-adoption-smoke --path .
cargo xtask external-adoption-smoke --path . --format json
```

Local path mode must create clean temporary projects under the repository's
`target/external-adoption-smoke/` tree, use the current checkout through path
dependencies or a local CLI binary, and run only documented user-facing
commands. Generated fixture payloads and temp project outputs must stay under
that `target/` subtree.

Published-version mode is an audit/reference mode:

```bash
cargo xtask external-adoption-smoke --version 0.9.1
```

Published-version mode may install or depend on the named crates.io version. It
must not prepare, tag, publish, or otherwise imply release execution for a new
version.

The command must write receipts:

```text
target/external-adoption-smoke/report.md
target/external-adoption-smoke/report.json
```

The receipts must summarize:

- command mode (`path` or `version`);
- repo path or published version used;
- temp project paths;
- snippets or examples exercised;
- CLI commands run;
- bundle profiles generated;
- verify/inspect results;
- generated output roots;
- skipped checks and skip reasons;
- failure command, stdout/stderr pointers, and remediation hints where
  practical.

The initial adoption matrix must cover these user jobs:

| User job | Required smoke shape |
| --- | --- |
| Rust test fixtures | A clean Cargo project that depends on the facade crate and runs a small deterministic fixture test. |
| Scanner-safe bundle | Installed-style CLI generation plus `verify-bundle` and `inspect-bundle` for the scanner-safe profile. |
| TLS verifier fixtures | Installed-style CLI generation plus `verify-bundle` and `inspect-bundle` for the TLS profile. |
| OIDC/JWKS verifier fixtures | Installed-style CLI generation plus `verify-bundle` and `inspect-bundle` for the OIDC profile. |
| Webhook verifier fixtures | Installed-style CLI generation plus `verify-bundle` and `inspect-bundle` for the webhook profile. |

Installed-style CLI commands should prefer the product surface:

```bash
uselesskey profiles
uselesskey profile webhook --explain
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey verify-bundle --path target/uselesskey-webhook
uselesskey inspect-bundle --path target/uselesskey-webhook
```

The smoke command may use a local binary path in `--path .` mode, but receipts
and docs must make that local substitution visible.

## Non-goals

This spec does not prepare or cut v0.10.0.

This spec does not require a version bump, tag, crates.io publish, GitHub
release, or shipper migration.

This spec does not add a new public claim, contract pack, README badge, fixture
family, provider compatibility matrix, or production security assurance.

This spec does not move claim-proof, verification-pack, or release evidence out
of repo-local `xtask` commands.

This spec does not permit installed CLI proof commands to shell out to ambient
`cargo xtask` commands or execute claim-ledger strings.

This spec does not require copying generated secret-shaped payloads into a
shareable reviewer bundle.

## Required Evidence

Docs-only changes to this spec should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

The initial command implementation should run:

```bash
cargo test -p xtask external_adoption_smoke
cargo xtask external-adoption-smoke --path .
cargo xtask external-adoption-smoke --path . --format json
cargo xtask pr-lite
git diff --check
```

Clean-project example changes should run:

```bash
cargo xtask external-adoption-smoke --path .
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines local path mode for clean-project adoption smoke;
- it defines published-version mode as audit/reference only;
- it defines Markdown and JSON receipt paths;
- it names the initial Rust test, scanner-safe, TLS, OIDC/JWKS, and webhook
  adoption jobs;
- it requires generated outputs to stay under `target/`;
- it keeps installed CLI commands separate from repo-local proof commands;
- it preserves claim and production-security boundaries.

This spec is implemented when:

- `cargo xtask external-adoption-smoke --path .` creates clean projects and
  proves the initial adoption matrix;
- `--format json` writes `target/external-adoption-smoke/report.json`;
- the default Markdown receipt writes
  `target/external-adoption-smoke/report.md`;
- `--version <published>` exercises a crates.io version without release action;
- generated fixture payloads and temp-project output stay under `target/`;
- failures name the project, command, and reproducible next command;
- external adoption can be run from adoption-regression only through an explicit
  external flag.

## Acceptance Examples

Valid local path smoke:

```bash
cargo xtask external-adoption-smoke --path .
```

Valid receipt summary:

```text
external-adoption-smoke: pass
mode: path
source: C:\Code\Rust\uselesskey

projects:
- rust-test-fixtures: pass
- scanner-safe-cli: pass
- tls-cli: pass
- oidc-cli: pass
- webhook-cli: pass

outputs:
- target/external-adoption-smoke/work/webhook-cli/target/uselesskey-webhook
```

Valid published-version audit:

```bash
cargo xtask external-adoption-smoke --version 0.9.1
```

Invalid release trigger:

```text
external-adoption-smoke --version 0.10.0
  -> bumps Cargo.toml versions
  -> tags v0.10.0
  -> publishes crates
```

Invalid proof claim:

```text
External adoption smoke passed, so release evidence is complete.
```

Use this instead:

```text
External adoption smoke passed for clean-project user paths. Release evidence
and claim-proof remain separate repo-local proof surfaces.
```

## Test Mapping

External adoption smoke maps to:

- `cargo xtask external-adoption-smoke --path .` for current-checkout adoption;
- `cargo xtask external-adoption-smoke --path . --format json` for
  machine-readable receipts;
- `cargo xtask external-adoption-smoke --version <published>` for crates.io
  audit/reference smoke;
- generated clean Cargo projects for documented dependency snippets;
- installed-style CLI runs for profile discovery, bundle generation,
  `verify-bundle`, and `inspect-bundle`;
- `cargo xtask docs-sync --check` for documented snippet drift;
- `cargo xtask user-path-smoke` and `cargo xtask adoption-regression` as
  repo-local complements, not replacements;
- `cargo xtask no-blob` and file-policy checks where generated-output posture
  changes.

## Implementation Mapping

External adoption smoke is owned by:

- `xtask` command parsing and receipt code for `external-adoption-smoke`;
- `target/external-adoption-smoke/` for temp projects, generated outputs, and
  receipts;
- `examples/external/` for clean-project examples once added;
- `crates/uselesskey-cli` for installed-style profile, bundle, verify, and
  inspect commands;
- `docs/how-to/start-here.md`, `docs/contract-packs/`, and task-first how-tos
  for the copyable user paths;
- `USELESSKEY-SPEC-0012` for the CLI proof handoff boundary.

## CI Proof

Docs-only spec PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Initial tooling PR:

```bash
cargo test -p xtask external_adoption_smoke
cargo xtask external-adoption-smoke --path .
cargo xtask external-adoption-smoke --path . --format json
cargo xtask pr-lite
git diff --check
```

External adoption plus regression PR:

```bash
cargo xtask adoption-regression
cargo xtask adoption-regression --external
cargo xtask external-adoption-smoke --path .
cargo xtask pr-lite
git diff --check
```

## Metrics / Promotion Rule

This spec remains `accepted` while the lane builds the smoke command, examples,
docs separation, and optional adoption-regression external mode.

It can move to `implemented` when:

- local path mode covers the initial adoption matrix;
- published-version mode is available and documented as audit/reference only;
- receipts are stable enough to use in PR and closeout evidence;
- docs route installed users to `uselesskey ...` commands before `xtask`;
- the lane closeout records no version bump, tag, publish, new badge, or new
  contract pack.
