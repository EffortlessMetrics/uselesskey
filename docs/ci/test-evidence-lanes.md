# Test evidence lanes

`uselesskey` uses separate evidence lanes so routine pull requests stay fast while release-risk changes still get runtime mutation proof.

## Lane map

| Lane | Trigger | Evidence | Blocking posture |
| --- | --- | --- | --- |
| PR fast gate | Every pull request | formatting, clippy, impact-scoped tests, docs/public-surface/publish checks, examples smoke, no-blob, and RIPR oracle-exposure review | Blocking for normal gate failures and severe public-owner exposure gaps |
| PR targeted mutation | Label, high-risk paths, or explicit maintainer request | small `cargo mutants` slice for touched owner crates | Blocking only when triggered |
| Nightly mutation | Scheduled and manual workflow dispatch | mutation runs for public owner crates, adapters, all crates, or one requested crate | Advisory until release readiness consumes the receipts |
| Release preflight mutation | Release branch or tag candidate | full survivor-regression check for public owner crates and adapters | Blocking |

## Evidence types

- **Coverage** is execution-surface evidence: it tells us which code executed, not whether tests would detect wrong behavior.
- **RIPR** is static oracle-exposure evidence: it asks whether changed behavior appears reachable and revealed by meaningful test oracles.
- **Targeted mutation** is runtime confirmation for changed risk: it runs concrete mutants where a PR changes high-risk behavior.
- **Nightly mutation** is survivor-regression evidence: it keeps a slower full-mutation picture outside the normal PR critical path.
- **Release mutation** is the ship gate: unresolved survivor increases in public owner crates must be classified or fixed before release.

RIPR is not a replacement for mutation testing; it is the PR-time exposure filter.

## Commands

Default PRs run:

```bash
cargo xtask pr
cargo xtask ripr-pr
```

Targeted PR mutation is explicit:

```bash
cargo xtask mutants-pr --changed
cargo xtask mutants-pr --crate uselesskey-token
```

Nightly/manual mutation uses scopes:

```bash
cargo xtask mutants-nightly --scope public
cargo xtask mutants-nightly --scope adapters
cargo xtask mutants-nightly --scope all
cargo xtask mutants-nightly --scope crate --crate-name uselesskey-core
```

## Policy

Normal PRs should not pay for full workspace mutation. Maintainers should trigger targeted mutation when a PR touches derivation identity, seed/hash/stable bytes, negative fixture behavior, materialization or receipt semantics, adapter conversions, or any public fixture owner internals. Topology and release-risk PRs may still carry full owner mutation evidence in their PR bodies.
