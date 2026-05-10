# Release

## Status

Use this document for the steady-state crates.io release flow.

Release readiness is gated by:

- `cargo xtask docs-sync --check`
- `cargo xtask economics`
- `cargo xtask audit-surface`
- `cargo xtask publish-preflight`

## Publish order

The authoritative publish order is the `PUBLISH_CRATES` constant in
`xtask/src/main.rs`. It is a topo-sorted list of publishable crates, leaves
first.

The important public-order constraint for the current lane split is:

1. `uselesskey-entropy`
2. `uselesskey-cli`
3. `uselesskey`

The facade package step depends on the new entropy crate being available on
crates.io, so do not publish the facade first.

Do **not** maintain a separate crate list here — `PUBLISH_CRATES` is the
single source of truth.

For support expectations and intended audiences, reference the generated
[support matrix](../reference/support-matrix.md) before changing publish scope.

## Dry run

```bash
cargo xtask publish-preflight   # metadata + doc snippet versions + cargo package
cargo xtask publish-check       # cargo publish --dry-run in dependency order
```

Before tagging, make sure the release PR has already:

- bumped publishable crate versions
- updated `CHANGELOG.md`
- refreshed versioned `uselesskey*` dependency snippets in README/doc examples
- refreshed receipt docs via `cargo xtask economics` and `cargo xtask audit-surface`
- generated scanner-safe bundle proof with
  `cargo xtask bundle-proof --profile scanner-safe --out target/release-evidence/scanner-safe`
- generated OIDC contract-pack proof with
  `cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc`
- generated release evidence with
  `cargo xtask release-evidence --version 0.7.0 --out target/release-evidence`
- mapped release checklist lines in
  [`docs/release/v0.7.0-checklist.md`](../release/v0.7.0-checklist.md)
- reviewed the release category notes in
  [`docs/release/v0.7.0-category-notes.md`](../release/v0.7.0-category-notes.md)
- prepared the post-release audit checklist in
  [`docs/release/post-release-audit.md`](../release/post-release-audit.md)

## Publish

```bash
cargo xtask publish   # publishes crates in dependency order with retry
```

This command handles crates.io indexing lag automatically. Current behavior:

- retries each crate up to 5 times
- waits 60 s for indexing-race failures (`failed to select a version`, `not found`)
- backs off on rate limits (`429` / `too many requests`) with `120 s * attempt`
- treats "already uploaded" / "already exists" as success for reruns
- waits 30 s after each successful publish for indexing

## Post-release audit

After publishing, run the
[post-release audit](../release/post-release-audit.md) before broad
announcement. The audit verifies GitHub release visibility, crates.io/docs.rs
state, scanner-safe bundle verification, and evidence artifact links.
