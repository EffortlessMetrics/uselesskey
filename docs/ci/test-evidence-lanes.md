# Test evidence lanes

`uselesskey` uses several kinds of test evidence because no single tool answers every quality question quickly enough for every branch.

## Evidence types

| Evidence | What it proves | Where it belongs |
| --- | --- | --- |
| Coverage | The execution surface reached by tests. | Advisory trend signal and release context. |
| ripr | Static, diff-oriented oracle-exposure evidence: changed behavior appears to be checked by meaningful tests. | Default PR lane. |
| Targeted mutation | Runtime confirmation that concrete mutants in changed high-risk code are killed. | PRs with mutation labels or risky paths. |
| Nightly mutation | Broader survivor-regression evidence across public owner crates and adapters. | Scheduled/manual workflow. |
| Release mutation | Ship gate for public owner crates and release-critical adapters. | Release branches or tag candidates. |

ripr is not a replacement for mutation testing; it is the PR-time exposure filter.

## Lanes

| Lane | Trigger | Signal | Blocking posture |
| --- | --- | --- | --- |
| PR fast gate | Every pull request. | fmt, clippy, impacted tests, docs/public-surface/publish checks, examples smoke, no-blob, and `cargo xtask ripr-pr`. | Blocking for normal gates and severe ripr gaps on touched public owner crates. |
| PR targeted mutation | `mutation` label initially; high-risk path and ripr-driven triggers can be added later. | `cargo xtask mutants-pr --changed` over touched owner crates, capped for normal PRs. | Blocking only when the lane is triggered. |
| Nightly mutation | Schedule plus manual dispatch. | `cargo xtask mutants-nightly --scope public` by default. | Advisory first; release readiness consumes the receipts. |
| Release preflight mutation | Release branch or tag candidate. | Full mutation for public owner crates and release-critical adapters. | Blocking before ship. |

## Policy

Normal PRs should answer whether the change builds, keeps public surface promises, preserves docs/examples, avoids secret-shaped blobs, and appears to have a test oracle. They should not spend every run proving the entire repository mutation posture.

Run targeted PR mutation when a change touches derivation identity, hash/seed/stable byte semantics, negative fixtures, adapter conversions, bundle receipts, or other public fixture owner internals. Full mutation remains the right exception for topology or release-risk PRs.

Nightly mutation writes receipts under `target/mutation/` so release review can check survivor regressions, classified known survivors, and unviable mutants without hiding that evidence inside one giant PR job.
