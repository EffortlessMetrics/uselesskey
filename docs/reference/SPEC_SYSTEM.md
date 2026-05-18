# Repo Source-of-Truth System

`uselesskey` uses a linked source-of-truth stack so humans and agents can find
why work exists, what behavior is required, what decisions constrain it, what
lands next, and what proof supports public claims without relying on chat
history.

## Stack

```text
Roadmap
  -> Proposal
    -> Spec
      -> ADR
        -> Implementation plan
          -> Active goal
            -> PR
              -> Proof
```

## Artifact Roles

| Artifact | Owns | Does not own |
| --- | --- | --- |
| Roadmap | Release direction, milestone framing, lane discovery | Detailed PR queue, live proof receipts |
| Proposal | Why a lane exists, affected users, alternatives, risks, success criteria | Behavior contract, PR ordering |
| Spec | Required behavior, acceptance examples, evidence, test and CI mapping | Product rationale, implementation sequence |
| ADR | Durable architecture or operating decision, context, consequences | Current task list, metric state |
| Plan | Work-item sequence, dependencies, proof commands, rollback, closeout | Product strategy, durable architecture decisions |
| Active goal | Current machine-readable lane state, work items, proof commands, claim boundaries | Generated status, long-form rationale, historical closeout |
| Support/status docs | Public claims, tiering, known limitations, promotion proof | Feature design, task queue |
| Policy ledgers | Exceptions, owners, reasons, coverage, review dates | Broad architecture rationale |
| Handoffs/learnings | Session facts, proof run, durable lessons | Active execution source of truth |

## Source-of-Truth Locations

| Question | Source of truth |
| --- | --- |
| Why are we doing this? | `docs/proposals/` |
| What must be true? | `docs/specs/` |
| What decision constrains it? | `docs/adr/` |
| What PR lands next? | `plans/<lane>/implementation-plan.md` |
| What is the agent actively executing? | `.uselesskey/goals/active.toml` |
| What proves the claim? | `docs/status/`, receipts, CI output |
| What exceptions exist? | `policy/*.toml` |

## Rules

1. Keep one kind of truth per artifact.
2. Work on one semantic artifact or one implementation work item per PR unless
   the selected plan item explicitly says otherwise.
3. Proposals explain why; specs define behavior; ADRs record durable decisions;
   plans define sequencing; active goals define current execution.
4. Public claims require support/status proof or an equivalent claim-ledger
   pointer.
5. Policy exceptions require an owner, reason, coverage, and review date.
6. Generated status and receipts are updated by their generator/checker command,
   not by hand.
7. Proof commands must run before success is claimed; unavailable proof must be
   reported with the command, reason, substitute evidence if any, and whether it
   blocks merge.
8. Claim boundaries are part of the artifact contract. Do not broaden support,
   security, or provider-compatibility claims without the matching spec and
   proof update.

## Required Metadata

New source-of-truth proposals, specs, ADRs, and plans should include metadata for
these fields, using `n/a` or an empty list where a field does not apply:

- `Status`
- `Owner`
- `Created`
- `Linked proposal`
- `Linked specs`
- `Linked ADRs`
- `Linked plan`
- `Linked issues`
- `Linked PRs`
- `Support-tier impact`
- `Policy impact`

The existing repository templates in `docs/templates/` encode these as TOML
front matter for proposals, specs, and ADRs.

## Agent Workflow

Agents must begin by reading repo instructions and then this stack in order:

1. `AGENTS.md` or `CLAUDE.md`.
2. `docs/reference/SPEC_SYSTEM.md`.
3. `.uselesskey/goals/active.toml`.
4. The linked implementation plan for the selected ready work item.
5. The linked proposal only for why-level context.
6. The linked spec for behavior and acceptance.
7. Any linked ADRs for constraints.
8. Current `git status` before editing.

After startup, agents should pick exactly one ready work item, implement only
that item, run the listed proof commands plus `git diff --check`, and update
only the docs, status, receipts, or policy files required by that work item.

## Stop Conditions

Stop and report instead of guessing when:

- `.uselesskey/goals/active.toml` is missing, stale, or paused without a selected
  lane;
- linked proposals, specs, ADRs, or plans do not exist;
- the selected work item is missing proof commands;
- proof commands cannot run and no substitute evidence is defined;
- generated status differs from committed status before the work item begins;
- unrelated staged changes are present;
- the requested work conflicts with an ADR or spec;
- a public claim lacks a support/status proof pointer.

## Active Goal Lifecycle

The active goal manifest lives at `.uselesskey/goals/active.toml`.

- `status = "active"` means agents may select ready work items from it.
- `status = "paused"` must include a reason and means agents should not invent a
  new lane.
- Completed or superseded manifests move to
  `.uselesskey/goals/archive/YYYY-MM-DD-<lane>.toml` before a new active manifest
  is created.

Do not leave multiple active goals.

## Closeout Format

At the end of a lane, write `plans/<lane>/closeout.md` with:

- shipped work;
- proof commands and receipts;
- PRs and CI runs;
- generated status, support-tier, and policy updates;
- deferred work;
- claim boundary;
- next lane recommendation.

Closeout prevents future agents from rediscovering old work.

## Common Failure Modes

### Spec becomes a task list

Move PR order to `plans/<lane>/implementation-plan.md`; keep the spec to
behavior, examples, and proof.

### Plan becomes product rationale

Move why-level prose to `docs/proposals/`; keep the plan to work items,
acceptance, proof, and rollback.

### Active goal becomes prose

Keep `.uselesskey/goals/active.toml` machine-readable and link out to docs for
long explanations or generated tables.

### Agent hand-edits generated status

Run the generator/checker named in the selected plan item instead of editing
receipts or generated endpoints by hand.

### Support claims drift

Add or update support/status proof before broadening README, how-to, badge, or
CLI claims.

### Policy exceptions become silent debt

Every exception needs owner, reason, `covered_by`, `review_after`, and optional
`expires` metadata.

### Mega PR

Split the change so one PR owns one semantic artifact or one implementation work
item.

## What Good Looks Like

A new contributor or agent can arrive cold and answer:

```text
What are we doing?
Why?
What must be true?
What decision constrains it?
What PR lands next?
What command proves it?
What may we claim?
What must we not claim?
```

If the repo answers those questions without chat history, the source-of-truth
system is working.
