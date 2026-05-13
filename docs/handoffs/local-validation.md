# Local Validation and Evidence Routing

Use this handoff when preparing, reviewing, or reporting local PR evidence.
Local evidence is useful only when its boundary is explicit.

## First Command

For non-trivial repo work, start with:

```bash
cargo xtask pr-lite
```

`pr-lite` is the bounded local approximation of hosted PR CI. It writes:

```text
target/pr-lite/pr-lite.json
target/pr-lite/pr-lite.md
```

Use those receipts to report what ran locally, what skipped, and what hosted CI
still owns.

## What PR-Lite Covers

`pr-lite` focuses on cheap, deterministic checks:

- source-of-truth drift with `cargo xtask spec-check --strict`;
- docs synchronization with `cargo xtask docs-sync --check`;
- file policy, no-blob, and public-surface checks;
- impacted-evidence routing;
- existing `ripr` PR artifact contracts when artifacts exist;
- cheap focused test paths such as xtask tests, examples smoke, BDD checks, or
  fuzz build when the changed paths justify them.

It does not replace `cargo xtask pr`, hosted CI, targeted mutation, full fuzzing,
or release evidence.

## Heavy Evidence Routing

Use the mutation routing receipt when targeted mutation is surprising or slow:

```bash
cargo xtask mutants-pr --changed --explain
```

The receipt lives under:

```text
target/xtask/mutation-routing/latest.json
target/xtask/mutation-routing/latest.md
```

It should explain:

- changed files considered;
- owner crates selected;
- whether targeted mutation is required;
- RIPR severe-gap routing;
- labels that hosted CI may consider;
- selected mutation command;
- whether diff-scoped mutation is available;
- fallback reason when crate-scope mutation is used.

Diff-scoped mutation is allowed only when changed owner paths map cleanly to
Rust hunks. If mapping, diff generation, or diff-file writing fails,
`mutants-pr` falls back to crate-scope mutation and records the reason.

`--full-owner` is intentionally crate-scoped. Do not describe it as
diff-scoped proof.

## Reporting Language

Use precise validation language in PR bodies and handoffs.

Say:

```text
Local PR-lite passed; hosted CI and full PR evidence remain separate.
```

Say:

```text
cargo xtask pr passed locally.
```

Only say:

```text
All required gates passed.
```

after the relevant local command and hosted required checks have completed.

Do not use `pr-lite` success to claim release readiness, mutation adequacy,
runtime correctness, or public-claim proof.

## Evidence Map

Docs-only PRs usually need:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Non-trivial code or xtask PRs should add:

```bash
cargo xtask pr-lite
cargo xtask pr
```

Public-claim changes should add:

```bash
cargo xtask claim-report --check-public-claims
```

Contract-pack changes should add:

```bash
cargo xtask contract-packs --check
```

Mutation-routing changes should add:

```bash
cargo xtask mutants-pr --changed --explain
```

Release work remains separate. Use release-evidence commands from
`docs/specs/USELESSKEY-SPEC-0006-release-evidence-lanes.md`.
