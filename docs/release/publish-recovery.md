# Publish recovery and registry-truth rules

This document defines the release-process posture for partial-publish
incidents. Operational steps live in
[`docs/how-to/recover-partial-publish.md`](../how-to/recover-partial-publish.md);
this is the policy/why side.

## Registry truth

crates.io is the immutable source of truth. Once `<crate>@<version>`
is uploaded, the release process treats that as the final state of
that crate at that version. The local `publish-state.json` is a
record of intent; crates.io is the record of fact.

When the two disagree, prefer crates.io.

## Recovery posture by failure class

| Failure class | Recovery | Retag? | Restart? |
| --- | --- | --- | --- |
| Indexing race / readiness lag | retry with backoff | no | no |
| Single-crate metadata error | patch + `--from <crate>` | no | no |
| Dependency-order error | patch PUBLISH_CRATES + `--from <crate>` | no | no |
| Workspace verification error (versioned publish-false dep, etc.) | patch workspace.dependencies + `--from <crate>` | no | no |
| Tag points at wrong commit | delete tag, retag, push | yes (rare) | yes |
| Shipper plan defect | revert to cargo xtask publish, `--from <crate>` | no | no |
| Auth/token issue | rotate token, retry | no | no |

## Tag-touching is the exception

The release tag (e.g. `v0.7.0`) should be deleted+recreated only when
the tag commit itself was the wrong commit. If `main` has been
patched after the partial publish and the new commits are the
intended release content, retagging to that new HEAD is correct.

If `main` is unchanged and only the workspace state needs to be
reinspected, do NOT retag — dispatch the publish-retry workflow
instead.

## When to yank

Yank a published version only when:

- the artifact has a critical defect that would mislead downstream
  consumers, and
- a fixed version is being prepared on a higher patch number.

Yanks suppress new resolution but keep the artifact queryable. Do not
yank to "clean up" a partial publish; that leaves a half-yanked
history that downstream consumers must navigate.

## Publish-system hardening

The v0.7.0 release lane exposed three publish-system gaps that are
being closed in v0.7.1:

1. **Publish graph topology** — #572: PUBLISH_CRATES must be
   dependency-topological; verified at PR time.
2. **Versioned publish-false workspace deps** — (PR 2 of v0.7.1):
   `workspace.dependencies` entries pointing at `publish = false`
   crates must be path-only.
3. **Scanner-safe reference drift** — (PR 3 of v0.7.1):
   `examples/scanner-safe-bundle/expected/*` is verified against
   regenerated outputs at PR time.

See [`v0.7.0-lessons-learned.md`](v0.7.0-lessons-learned.md) for the
incident retrospective.

## Shipper status

Migration to `shipper` for publish is parked behind
EffortlessMetrics/shipper#173 (non-topological plan ordering). The
current path is `cargo xtask publish` via `release.yml` and
`publish-retry.yml`. Re-migration happens after shipper's next patch
ships and the plan ordering is verified against this workspace's DAG.
