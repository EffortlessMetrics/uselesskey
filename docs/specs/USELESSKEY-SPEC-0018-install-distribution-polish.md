+++
id = "USELESSKEY-SPEC-0018"
kind = "spec"
title = "Install and distribution polish"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
linked_plan = "plans/usability-polish/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0012",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0017",
]
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0018: Install and Distribution Polish

## Problem

`uselesskey` has strong repo-local proof and an installed CLI loop, but the
front door still has to make the product obvious to someone who did not build
the repo.

The installed user should see:

```text
what uselesskey does
  -> how to install it or add the facade crate
    -> how to self-check the CLI
      -> how to generate and audit fixtures
        -> what the receipt proves and does not prove
```

This spec defines install and distribution polish for the v0.10.0 product
quality target. It does not start release prep.

## Behavior

Docs and installed CLI surfaces must present these user paths before internal
proof machinery:

| User | First interface | Expected first command or snippet |
| --- | --- | --- |
| Installed CLI user | `uselesskey` | `cargo install uselesskey-cli --version <current-stable>` |
| Rust test author | facade crate | `uselesskey = { version = "<current-stable>", ... }` |
| CI user | installed CLI | `uselesskey bundle ... && uselesskey audit-bundle ... --ci` |
| Reviewer with repo checkout | repo proof | `cargo xtask verification-pack ...` |
| Maintainer | repo proof | `cargo xtask pr`, `adoption-regression`, `release-evidence` |

The top-level README and task docs must keep the first screen focused on:

- generate deterministic auth, TLS, webhook, token, and test fixtures;
- keep raw generated material out of git by default;
- audit generated bundles with metadata-only receipts;
- upload audit receipts in CI;
- understand the proof boundary.

Installed CLI help and `doctor` output should answer installed-user questions:

- which command to run next;
- whether the CLI can write under `target/`;
- which profiles are known;
- whether JSON output is available;
- which operations are repo-local proof rather than installed-user setup.

## Non-goals

This spec does not:

- prepare, cut, tag, or publish v0.10.0;
- add binary release artifacts or checksums before the release lane chooses a
  distribution path;
- add new contract packs or fixture families;
- add README badges;
- make provider compatibility, production security, or scanner-policy bypass
  claims;
- require installed CLI commands to execute `xtask`, release evidence, or
  claim-ledger command strings;
- redesign the facade API broadly.

## Required Evidence

Install/distribution polish is proven by:

- docs that name the current stable install/dependency snippets;
- CLI help and `doctor` tests or smoke runs for installed-user behavior;
- `external-adoption-smoke --path .` for clean-project installed paths;
- `adoption-regression --external` when the change touches bundled user paths;
- `docs-sync`, `typos`, and `spec-check` for source-of-truth consistency.

## Test Mapping

| Requirement | Evidence |
| --- | --- |
| Current install/dependency snippets stay synced | `cargo xtask docs-sync --check` |
| Installed CLI commands work in clean projects | `cargo xtask external-adoption-smoke --path .` |
| Installed self-check remains machine-readable | `cargo test -p uselesskey-cli --all-features doctor` |
| Bundle audit remains metadata-only | `cargo test -p uselesskey-cli --all-features audit_bundle`; `cargo xtask no-blob` |
| Repo public claims remain separate | `cargo xtask claim-report --check-public-claims` in closeout |

## Implementation Mapping

| Surface | Owner |
| --- | --- |
| README/front door | `README.md` |
| Installed CLI help and doctor | `crates/uselesskey-cli/src/main.rs` |
| Clean-project smoke | `xtask/src/external_adoption_smoke.rs` |
| Bundle audit receipts | `docs/specs/USELESSKEY-SPEC-0014-installed-bundle-audit.md` |
| Bundle product surface | `docs/specs/USELESSKEY-SPEC-0017-bundle-product-surface.md` |
| Usability lane plan | `plans/usability-polish/implementation-plan.md` |

## CI Proof

Every PR in this spec lane must run the narrowest relevant proof plus the
standard docs/spec gates:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

PRs that touch installed CLI behavior must also run:

```bash
cargo test -p uselesskey-cli --all-features <focused-filter>
cargo xtask external-adoption-smoke --path .
```

## Acceptance

This spec is satisfied when:

- the front door names the installed CLI, Rust facade, CI audit, reviewer, and
  maintainer paths without leading with repo internals;
- copyable install and dependency snippets use the current stable version in
  current how-to docs;
- installed CLI help and `doctor` output answer installed-user next steps
  without requiring `xtask`;
- external adoption smoke proves the documented installed-user path;
- no doc in this lane implies release readiness, provider compatibility,
  production security, or scanner-policy bypass approval.

## Boundaries

Install polish may make `uselesskey` easier to adopt. It must not blur the
claim boundary:

- installed bundle audit proves local bundle consistency, not repo public
  claims;
- scanner-safe means the project classifies generated material as scanner-safe
  test fixtures, not approval to bypass scanner policy;
- generated fixtures do not prove production secret handling;
- TLS/OIDC/webhook fixtures do not prove provider compatibility or production
  security;
- release proof remains a release lane concern.
