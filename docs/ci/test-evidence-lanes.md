# Test evidence lanes

`uselesskey` uses separate evidence lanes so PRs stay fast while release-risk
changes still get strong proof. The key policy is:

> ripr is not a replacement for mutation testing; it is the PR-time exposure filter.

## Evidence types

| Evidence | What it answers | Where it belongs |
| --- | --- | --- |
| Coverage | Did tests execute the changed surface? | Advisory reports and release review. |
| ripr | Does changed behavior appear exposed to a meaningful oracle? | Every PR fast gate. |
| Targeted mutation | Do concrete mutants in the changed risk slice survive? | Labeled or high-risk PRs. |
| Nightly mutation | Did survivor posture regress across public owner crates? | Scheduled/manual mutation workflow. |
| Release mutation | Is mutation evidence clean enough to ship? | Release branches and tag candidates. |

## Lanes

### PR fast gate

Every PR runs normal gates plus `cargo xtask ripr-pr`:

```text
fmt
clippy
impact-scoped tests
docs-sync
public-surface
publish-preflight
examples-smoke
no-blob
ripr-pr
git diff --check
```

`cargo xtask ripr-pr` writes these artifacts:

```text
target/ripr/pr/repo-exposure.json
target/ripr/pr/summary.md
target/ripr/pr/review.md
```

The PR lane blocks only on severe repo-scoped exposure gaps for public owner
surfaces. Weak exposure remains review feedback unless the PR is explicitly
routed to targeted mutation.

### PR targeted mutation

Targeted mutation is selective. Run it manually or through the `mutation` label:

```bash
cargo xtask mutants-pr --changed
cargo xtask mutants-pr --crate uselesskey-token
```

Use `mutation/full` for topology or release-risk PRs that need a full owner
slice. Trigger targeted mutation for changes to derivation identity, seed/hash
stability, negative fixture behavior, bundle receipt semantics, or adapter
conversion behavior.

### Nightly mutation

The scheduled mutation workflow runs public owner crates by default:

```bash
cargo xtask mutants-nightly --scope public
```

Manual dispatch can select `public`, `adapters`, `all`, or one `crate`. Nightly
results are advisory for ordinary PR merge velocity, but survivor regressions
must be resolved or classified before release readiness.

### Release preflight mutation

Release candidates should run full mutation for public owner crates and relevant
adapters. A release cannot ship with unresolved survivor regression on public
owner surfaces, public-surface drift, publish dry-run failure, bundle verifier
failure, receipt drift, or scanner-safe/no-blob failure.
