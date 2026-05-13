+++
id = "USELESSKEY-SPEC-0005"
kind = "spec"
title = "Agent lane state"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = ["USELESSKEY-ADR-0003"]
linked_plan = "plans/spec-system/implementation-plan.md"
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0005: Agent Lane State

## Problem

Long-running repo work can drift when agents rely on stale chat prompts. A
session can keep replaying instructions after PRs have merged, after a lane has
changed state, or after a newer scope fence has narrowed the work.

`uselesskey` needs a repo-owned control plane that tells agents what is current
without making chat history the source of truth.

## Behavior

The current active agent lane is stored at:

```text
.uselesskey/goals/active.toml
```

The manifest must identify:

- lane `id`;
- human `title`;
- `status`;
- `owner`;
- `created` date;
- durable `objective`;
- concrete `end_state` items;
- current and recent `work_item` entries;
- linked proposal/spec/plan IDs or paths;
- validation `commands` for each work item.

Completed or superseded lane manifests move to:

```text
.uselesskey/goals/archive/
```

The active manifest is not a release note, how-to guide, or historical learning
record. It is the current execution state for agents.

Work items should use small status values:

```text
planned
ready
active
done
blocked
```

Active work items must link only to existing proposals, specs, and plans. Future
specs can be described in the implementation plan, but they should not be used
as active work-item links until the files exist.

## Non-goals

This spec does not replace GitHub issues, PRs, release notes, or changelog
entries.

This spec does not make agents authoritative over product truth. Specs, ADRs,
claim ledgers, and release evidence remain the durable sources for behavior and
proof.

This spec does not require every small docs PR to create a new active goal.
Use the manifest for multi-PR lanes where stale state is a real risk.

This spec does not implement `cargo xtask spec-check`; it defines the active
goal contract that command must later validate.

## Required Evidence

Docs-only active-goal changes should run:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

When `spec-check` exists, it must validate:

- `.uselesskey/goals/active.toml` parses as TOML;
- `status` is allowed;
- each work item has an `id`, `status`, `plan`, and `commands`;
- linked proposal and spec IDs exist;
- linked plans exist;
- active work items do not point to superseded specs.

## Acceptance

This spec is accepted when:

- `.uselesskey/goals/active.toml` exists for the spec-system lane;
- the active manifest links only to existing proposal/spec/plan artifacts;
- current work is described as lane state, not product truth;
- archive location and status values are defined.

This spec is implemented when:

- `cargo xtask spec-check` validates active goal manifests;
- lane closeout archives or updates `active.toml`;
- agents can continue the lane from the repo state without scraping chat.

## Acceptance Examples

Valid active work item:

```toml
[[work_item]]
id = "active-agent-lane-state"
status = "active"
proposal = "USELESSKEY-PROP-0001"
spec = "USELESSKEY-SPEC-0005"
plan = "plans/spec-system/implementation-plan.md"
commands = [
  "cargo xtask docs-sync --check",
  "cargo xtask typos",
  "git diff --check",
]
```

Invalid active work item:

```toml
[[work_item]]
id = "future-release-spec"
status = "ready"
spec = "USELESSKEY-SPEC-9999"
```

The linked spec does not exist, so future `spec-check` must reject it.

## Test Mapping

Current docs-only validation:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Future `spec-check` tests must cover TOML parsing, required active-goal fields,
work-item status validation, proposal/spec/plan link resolution, and archive
directory presence.

## Implementation Mapping

Agent lane state is owned by:

- `.uselesskey/goals/active.toml` for current lane state;
- `.uselesskey/goals/archive/` for completed or superseded lane manifests;
- `.uselesskey/goals/README.md` for directory rules;
- `plans/spec-system/implementation-plan.md` for PR sequencing;
- `docs/specs/USELESSKEY-SPEC-0005-agent-lane-state.md` for this contract;
- future `xtask spec-check` code for validation.

## CI Proof

Before `spec-check` exists:

```bash
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

After `spec-check` exists:

```bash
cargo xtask spec-check
cargo xtask spec-check --format json
```

Release closeout should use:

```bash
cargo xtask spec-check --strict
```

## Metrics / Promotion Rule

This spec remains `accepted` while active-goal validation is manual.

It can move to `implemented` when `spec-check` validates the active manifest and
the spec-system lane closeout archives or updates the manifest.
