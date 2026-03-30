# PR Bundle Reduction

Use the queue as keeper-based bundles, not as dozens of unrelated PRs.

## Why

- The open queue is large enough that GraphQL-heavy `gh pr list --json ...` calls are brittle.
- The stable collection path is the REST API through `gh api repos/<owner>/<repo>/pulls?...`.
- Bundles should be classified, assigned a keeper, and reduced with dedicated worktrees.

## Commands

Collect a live queue snapshot with the REST API:

```bash
cargo xtask pr-bundles snapshot --include-closed-paths
```

This writes `target/xtask/pr-bundles/snapshot.json` with:

- Open PRs
- Recent closed PRs for donor review
- Changed file counts, mergeable state, check buckets, and touched paths for open PRs
- Optional touched paths for closed donors when `--include-closed-paths` is enabled

Build a keeper ledger from that inventory:

```bash
cargo xtask pr-bundles ledger
```

This writes:

- `target/xtask/pr-bundles/ledger.json`
- `target/xtask/pr-bundles/ledger.md`

The ledger clusters PRs by normalized codex branch stem, highlights the first low-risk wave, recommends a keeper, and records harvest / validation / cleanup notes per bundle.

Prepare a dedicated worktree for one bundle keeper:

Use the bundle id from the generated ledger. For example, the March 28, 2026 snapshot produced `bundle-codex-implement-version-drift-enforcement-for-docs-19` for the docs/version-drift wave.

```bash
cargo xtask pr-bundles prepare --bundle-id <bundle-id> --keeper <pr-number>
```

By default this:

- Creates `../uselesskey-bundle-<bundle-id>`
- Creates `work/<bundle-id>-keeper`
- Fetches the keeper branch and checks it out into that worktree

Clean up a finished bundle worktree:

```bash
cargo xtask pr-bundles cleanup --bundle-id <bundle-id>
```

## Operating Rules

- Do not edit code before a keeper is explicit.
- Closed PRs are donors, not automatic resurrection candidates.
- Use one worktree per active bundle.
- Validate narrowly first, then run `cargo xtask gate`.
- After risky merges, wait for main push CI before advancing the next risky bundle.
