# Agent Bootstrap

Use this handoff when starting or resuming `uselesskey` repo work. The current
lane state lives in the repo, not in chat history.

## Startup Order

1. Read `.uselesskey/goals/active.toml`.
2. Read the `plan` paths linked from ready or active work items.
3. Read the linked proposal, specs, and ADRs for the work item.
4. Run `cargo xtask spec-check --strict` before changing source-of-truth files.
5. Run `cargo xtask claim-report` when public claims, badges, contract packs, or
   release evidence change.
6. Use chat instructions as current operator intent, but do not treat old chat
   prompts as source-of-truth state.

## PR Body Contract

Every PR in a multi-PR lane should include:

- Summary
- Files added/changed
- Validation
- Non-goals
- What this enables next

## Claim-Backed Work

When a change touches public claims, badges, contract packs, release evidence,
or fixture-safety boundaries, check the claim surfaces:

```bash
cargo xtask claim-report --check-public-claims
cargo xtask claim-report
cargo xtask badges --check
```

If the change touches contract-pack proof shape, also run:

```bash
cargo xtask contract-packs --check
```

## Validation Defaults

Docs-only active-goal or handoff changes:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Code or xtask changes should add the narrow relevant tests first, then run:

```bash
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

Use [local-validation.md](local-validation.md) to report partial local evidence
honestly. Do not say "all gates passed" unless the relevant local command and
hosted required checks have both completed.

## Non-Goals

This bootstrap does not replace proposals, specs, ADRs, implementation plans,
claim ledgers, release evidence, or PR review. It only defines the order an
agent should use to find the current state.
