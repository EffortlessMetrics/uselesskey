# How to: recover from a partial publish

Use this when `cargo xtask publish` or the `release.yml` workflow has
failed *after* one or more crates landed on crates.io. The operating
rule is simple: **crates.io is the source of truth**. Once a crate is
published at a version, it cannot be unpublished — only yanked. Plan
around that fact.

## Recognize a partial publish

You are in a partial-publish state when:

- The release workflow exited with `publish` job failure (not preflight).
- `cargo info <crate>` shows the new version live for at least one
  workspace crate but not the facade `uselesskey`.
- `target/xtask/publish-state.json` lists at least one crate with
  `status = "published"`.

## Inspect registry truth

For each PUBLISH_CRATES entry, query crates.io:

```bash
for c in $(jq -r '.crates[].name' target/xtask/publish-state.json); do
  v=$(curl -s "https://crates.io/api/v1/crates/$c" \
      | python -c "import sys,json; print(json.load(sys.stdin)['crate']['max_version'])")
  echo "$c: $v"
done
```

Cross-reference with `target/xtask/publish-state.json` to confirm what
shipper or `cargo xtask publish` thought it did.

## Choose the recovery path

### Recovery path A: resume from the failed crate

When the cause is transient (crates.io indexing race, network blip, a
single crate metadata error) and all earlier crates published cleanly:

```bash
gh workflow run publish-retry.yml \
  -f tag=<tag> \
  -f resume_from=<failed-crate-name>
```

`cargo xtask publish --from <crate>` walks PUBLISH_CRATES from that
index forward. Already-published crates are detected via
`cargo publish`'s `crate version already uploaded` error and recorded
as `already_published` in `publish-state.json`.

### Recovery path B: patch the workspace, then resume

When the cause is structural (incorrect dep order, manifest issue,
missing dep on crates.io):

1. Land the fix on `main` via a PR. Do not retag yet.
2. Once main is updated:
   - If the tag commit was the source of truth and `release.yml` is
     what dispatches publish: delete `<tag>` locally and on origin,
     retag main HEAD, push.
   - If you can recover via `publish-retry.yml` against main HEAD
     (no tag needed for that workflow's checkout), use that without
     retagging.
3. Treat partial-publish crates as fixed points. Do not try to
   republish the same version that already landed.

## Anti-patterns

- **Do not retag blindly** when crates have already landed at the
  target version. The retag does not unpublish, and re-running the
  workflow against a still-broken graph just re-attempts the same
  failures.
- **Do not yank** unless you have actively deployed broken artifacts.
  Yanked versions stay queryable; they only suppress new resolution.
- **Do not republish under a new version** (`0.7.0 → 0.7.0-fix`) when
  only some crates landed. The split history makes downstream
  resolution worse, not better.
- **Do not use retries to solve order failures.** Retries only help
  with crates.io indexing/readiness lag. Dependency-order failures are
  deterministic and will fail every attempt.

## Tooling that helps you avoid this

- `cargo xtask publish-check` — runs every PR and now (post-#572)
  verifies PUBLISH_CRATES is dependency-topological.
- `cargo xtask publish-preflight` — runs every PR and (post-PR 2 of
  the v0.7.1 series) rejects versioned `workspace.dependencies`
  entries that point at `publish = false` crates.
- `cargo xtask publish --dry-run --from <crate>` — dry-run a resume
  before live publish.

## Why shipper is parked

`shipper 0.3.0-rc.2` was migrated in #566 then reverted in #570
because its publish plan was not dependency-topological for this
workspace (tracked in EffortlessMetrics/shipper#173). The
`release.yml` / `publish-retry.yml` workflows use `cargo xtask publish`
for v0.7.x patch releases. Re-migration happens after shipper's next
patch resolves #173.
