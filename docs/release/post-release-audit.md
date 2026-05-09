# Post-Release Audit

Run this checklist after publishing a `uselesskey` release. It verifies that the
public fixture promises described in the release notes are visible to users and
that evidence artifacts remain reachable.

The audit is for release confidence, not production cryptographic assurance.
`uselesskey` remains a test-fixture layer.

## Inputs

- Release tag, for example `v0.6.1`.
- Published crate version, for example `0.6.1`.
- Release evidence matrix for the candidate commit.
- Release notes generated from `.github/release.yml`.

Set local variables before running commands:

```bash
TAG=v0.6.1
VERSION=0.6.1
```

## Immediate Checks

| Check | Command | Pass condition | If it fails |
| --- | --- | --- | --- |
| GitHub release is visible | `gh release view "$TAG"` | Draft is published, tag points at the intended commit, release notes include the fixture-platform claim boundary. | Fix release notes if only text is wrong; otherwise stop and investigate tag/commit mismatch. |
| Crates are visible | `cargo search uselesskey --limit 5` | The facade version appears on crates.io after indexing delay. | Wait for indexing; if still missing, inspect `cargo xtask publish` output and crates.io package pages. |
| Facade install path resolves | `cargo search uselesskey --limit 5` plus a fresh downstream smoke crate if needed | Users can resolve the published facade version. | Open a release issue and document dependency-order or indexing symptoms. |
| Docs.rs build started or completed | Open `https://docs.rs/crate/uselesskey/$VERSION` | docs.rs has accepted the package or shows a build in progress. | Track as a release issue; do not republish solely for docs.rs lag. |
| Release evidence is linkable | Review the release body and uploaded workflow artifacts | Evidence matrix, receipts, mutation/perf artifacts, and bundle proof are linked or referenced. | Patch release notes with missing links. |

## Public Promise Checks

Run these from a clean checkout or a temporary downstream smoke project once
crates.io indexing has settled:

```bash
cargo xtask public-surface
cargo xtask docs-sync --check
cargo xtask publish-preflight
cargo xtask no-blob
```

For bundle promises, regenerate and verify the default platform lane:

```bash
cargo run -p uselesskey-cli -- bundle --profile scanner-safe --out target/post-release-bundle
cargo run -p uselesskey-cli -- verify-bundle --path target/post-release-bundle
cargo run -p uselesskey-cli -- inspect-bundle --path target/post-release-bundle
cargo run -p uselesskey-cli -- export k8s \
  --bundle-dir target/post-release-bundle \
  --name uselesskey-fixtures \
  --namespace tests \
  --out target/post-release-bundle/secret.yaml
cargo run -p uselesskey-cli -- export vault-kv-json \
  --bundle-dir target/post-release-bundle \
  --out target/post-release-bundle/kv-v2.json
```

For evidence promises, confirm the latest release-candidate artifacts exist:

```bash
cargo xtask economics
cargo xtask audit-surface
cargo xtask perf --compare
cargo xtask mutants-nightly --scope public --dry-run
```

The dry-run mutation command verifies scope planning and survivor-ledger parsing.
Use the scheduled/manual mutation workflow result for actual survivor evidence.

## Audit Record

Record the audit in the release issue or post-release tracking issue with this
shape:

```markdown
## Post-release audit for v0.6.1

- Release visible: pass/fail, link
- Crates.io facade visible: pass/fail, link
- Docs.rs visible: pass/fail, link
- Public-surface/docs/package checks: pass/fail, command evidence
- Scanner-safe bundle verify/export/inspect: pass/fail, artifact path or link
- Receipts: pass/fail, economics/audit/perf/mutation artifact links
- Open follow-ups:
  - issue link or "none"
```

## Failure Handling

- Text-only release note issue: edit the GitHub release and note the correction
  in the audit record.
- Missing docs.rs build: open a follow-up issue and link the docs.rs build log.
- Crates.io publish gap: pause announcements until the missing crate or facade
  path is understood.
- Scanner-safe bundle regression: open a blocking patch issue; do not recommend
  the affected bundle path until a fix is released.
- Evidence artifact gap: attach the missing command output or explain why the
  evidence is not applicable for this release.
