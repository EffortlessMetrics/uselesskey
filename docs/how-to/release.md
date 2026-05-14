# Release

## Status

Use this document for the steady-state crates.io release flow.

Release readiness is gated by:

- `cargo xtask spec-check --strict`
- `cargo xtask claim-report --check-public-claims`
- `cargo xtask contract-packs --check`
- `cargo xtask docs-sync --check`
- `cargo xtask pr-lite`
- `cargo xtask pr`
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
- mapped release proof in the release-specific evidence matrix
- generated full minor-release evidence with
  `cargo xtask release-evidence --version <VERSION> --dry-run --summary`
- generated stable claim proof with `cargo xtask claim-proof --all-stable`
- generated a metadata-only verification pack with
  `cargo xtask verification-pack --out target/uselesskey-verification`
- generated TLS contract-pack proof with
  `cargo xtask bundle-proof --profile tls --out target/release-evidence/tls`
- generated OIDC contract-pack proof with
  `cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc`
- generated webhook contract-pack proof with
  `cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook`
- verified the no-panic-family policy posture with
  `cargo xtask check-no-panic-family`
- verified generated badge endpoint drift with `cargo xtask badges --check`
- prepared the post-release audit checklist in
  [`docs/release/post-release-audit.md`](../release/post-release-audit.md)

For v0.9.0, use
[`docs/release/evidence-matrix-v0.9.0.md`](../release/evidence-matrix-v0.9.0.md)
as the release-specific proof map.

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
