# PR Disposition Policy

This policy keeps queue review focused when multiple agents or dependency bots produce overlapping branches. The goal is one reviewed path to `main`, not many patched copies of the same idea.

## Dispositions

- **Keeper**: the canonical PR for a behavior change or dependency update. A keeper has a reviewed diff, green required checks, and enough tests to prove the fixture identity or shape contract it touches.
- **Duplicate**: a PR that solves the same collision cluster as a keeper. Close it after the keeper lands, with a comment naming the accepted PR and the reason this one is not kept.
- **Stale**: a PR whose base, dependency set, or branch intent no longer matches `main`. Rebase only if the change is still the best path; otherwise close it with the current replacement path.
- **Declined**: a PR that changes the wrong contract, weakens scanner-safe defaults, broadens scope, or adds unsafe automation. Close it with the concrete review reason.

## Collision Clusters

Use one canonical PR per collision cluster. A cluster is any set of PRs that touch the same fixture identity, encoding shape, dependency family, workflow, or public surface.

Pick the keeper by reviewing the behavior, not by arrival order. Prefer the branch that preserves deterministic compatibility, keeps short encodings stable, covers the full negative path, and avoids broad unrelated cleanup.

After the keeper merges:

- close duplicate branches instead of rebasing every copy;
- name the merged PR in each closure comment;
- call out any declined behavior that should not be reintroduced;
- leave follow-up work as a new narrow PR rather than reopening a mixed branch.

## Dependency PRs

Merge dependency PRs when the diff is narrow, the update is compatible with the current dependency lane, and CI starts from a clean advisory baseline.

Close or park a dependency PR instead of patching it when:

- it was generated before an advisory-floor repair and no longer reflects current `main`;
- it selects the wrong release line, such as an unaccepted prerelease family;
- it pulls unrelated lockfile churn into a code keeper;
- it masks a code-review issue that should be fixed in a product PR first.

For dependency clusters, land behavior keepers first when they touch the same crates. Then merge clean dependency bumps one at a time so any lockfile or backend regression is attributable.

## Mutation-Lane Failures

Treat a mutation failure as review feedback, not as noise to waive.

- If a mutant exposes missing behavior coverage, add a focused test for the fixture identity, encoding shape, or negative contract.
- If a mutant is equivalent but timeout-prone, prefer a clearer implementation shape over a test that only chases the mutation tool.
- Re-run the exact mutation target that failed before force-pushing the keeper.
- Do not weaken gold expectations or broad assertions just to reduce mutation count.

The accepted fix should explain what contract is now proven: stable bytes, byte-budget truncation, sequential handles, exact timestamp arithmetic, provider-specific secret shape, or another concrete fixture property.

## Automation Workflow PRs

Do not merge automation workflow PRs unless they satisfy all of these conditions:

- actions are pinned to a versioned tag or immutable SHA;
- permissions are minimal and declared explicitly;
- missing secrets produce a clean no-op, not a failure or partial publish;
- the workflow cannot publish, comment, or mutate repository state from untrusted input;
- the PR has a local or dry-run proof for the path it enables.

If those conditions are missing, close the PR as declined. Do not patch around an unsafe workflow proposal by adding broad permissions or unpinned actions.

## Review Order

1. Repair the shared runway first: advisory floors, CI gates, and dependency guards.
2. Merge reviewed code keepers with green checks.
3. Close duplicates and declined branches with explicit comments.
4. Merge clean dependency bumps one at a time.
5. Update roadmap or governance docs only after the queue state is true on `main`.

Never merge a red or pending PR just to reduce queue size. A correct disposition is better than a fast merge.
