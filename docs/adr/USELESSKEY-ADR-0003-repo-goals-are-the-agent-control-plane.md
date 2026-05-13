+++
id = "USELESSKEY-ADR-0003"
kind = "adr"
title = "Repo goals are the agent control plane"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = ["USELESSKEY-SPEC-0005"]
+++

# USELESSKEY-ADR-0003: Repo Goals Are the Agent Control Plane

## Decision

For multi-PR lanes, `uselesskey` will use `.uselesskey/goals/active.toml` as
the current agent control plane.

Agents should read the active goal manifest and linked proposal/spec/plan files
before continuing lane work. Chat handoffs can point to those files, but they
should not be the only durable state.

## Context

The spec-system lane exists partly because stale prompts can continue to issue
old instructions after the repo has moved. That is especially risky for release
work, public proof claims, and long PR queues where the right next step changes
as PRs merge.

The repo already has proposals, specs, ADRs, claim ledgers, generated endpoints,
and release evidence. Active agent state should join that system instead of
living only in a chat transcript.

## Consequences

Agents get a stable starting point for current work.

Maintainers can review lane state in PRs rather than reconstructing it from
session logs.

Closeout becomes explicit: archive or update the active manifest when a lane
finishes.

The manifest can drift if it is not validated. Future `cargo xtask spec-check`
must validate links, statuses, and active work items.

## Alternatives Considered

Use chat handoffs only.

Rejected because handoffs are easy to stale and hard for future sessions to
audit against repo state.

Use GitHub issues only.

Rejected because issues are useful coordination surfaces but do not live in the
workspace where agents can parse them without network context.

Put active instructions in `AGENTS.md`.

Rejected because `AGENTS.md` should hold stable operating guidance, not
lane-specific work items.

Create a heavyweight project-management system.

Rejected because this repo needs a small TOML manifest linked to specs and
plans, not a separate workflow platform.

## Follow-up Specs / Plans

- `USELESSKEY-SPEC-0005` defines active-goal manifest requirements.
- `plans/spec-system/implementation-plan.md` tracks the remaining rollout.
- Future `cargo xtask spec-check` should validate active goal links and status.
