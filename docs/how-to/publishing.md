# Crates.io readiness and publishing playbook

`main` is already in the crates.io-ready state. The publish-prep work landed in
`#229`; this document records the invariants to keep true for future releases:

- Main stays boring-green (repeatable CI, no flaky hangs, no “works on my machine” gaps)
- Every publishable crate packages cleanly (as crates.io sees it)
- Publishing is dependency-ordered and automatable (so releases are routine)

The goal is to make that state explicit and checkable.

## What “ready” means in practice

### Required gates (local + CI)

These are the minimum gates to treat as non-negotiable for a publishable workspace.

- `cargo xtask fmt`
- `cargo xtask clippy` (with `-D warnings`)
- `cargo xtask test`
- `cargo xtask docs-sync --check` (includes support-matrix generation + metadata validation)
- `cargo xtask feature-matrix` (or your feature sweep)
- `cargo xtask bdd` (use `--release` if crypto/keygen makes debug too slow)
- `cargo xtask publish-preflight` (metadata, doc snippet versions, cargo package)
- `cargo xtask publish-check` (cargo publish dry-run in dependency order)
- `cargo fuzz build` (compile-only in CI; running fuzz can be scheduled/nightly)

If CI does not run one of these, it is not a gate.

### Optional hardening

- mutation testing (`cargo mutants`) on a schedule or manual trigger
- `cargo deny` (licenses, bans, advisories)
- MSRV enforcement (matches `rust-version`)
- periodic “minimal versions” check (nightly)

## Correctness track

This track keeps `main` green and deterministic.

### Termination guarantees for RNG-driven code

If a function accepts `RngCore`, assume it may receive:

- deterministic test RNGs
- adversarial fuzz RNGs
- “constant output” stubs

Rule: rejection sampling must have a progress guarantee or it is a CI liability.

Common failure mode: an infinite loop when an RNG returns only rejected bytes.

Mitigation:

- keep unbiased rejection sampling as the fast path
- if a whole buffer produces zero accepted bytes, use a bounded deterministic fallback for that buffer

Regression requirement:

- include a unit test with a pathological RNG (for example `0xFF`) to prove termination.

### CI parity with local gates

CI should run the same commands that define local readiness. Common “surprise” gaps are:

- publish preflight not running in CI
- feature matrix missing `--no-default-features` / `no_std` coverage
- docs.rs feature mismatch with CI

## Publish hygiene track

This track prevents “works in workspace, but not publish.”

### Which crates are publishable

Each crate should be explicitly one of:

- Publishable (intended for crates.io)
- Non-publishable (internal tooling/test harnesses)

Use [`docs/reference/support-matrix.md`](../reference/support-matrix.md) as the generated source of truth for this contract (tier, publish status, audience, and semver expectations) rather than maintaining hand-written crate lists.

For non-publish crates:

```toml
[package]
publish = false
```

Common non-publish crates:

- `xtask`
- `fuzz` (if a crate)
- BDD step crates / internal test harness crates
- CI helpers

### Workspace dependency policy

For internal workspace crates:

- do not use `path = "../some-crate"` without a version for deps that must resolve on crates.io
- prefer `workspace = true` with `[workspace.dependencies]` entries that include both `path` and `version`

### Required crates.io metadata

Each publishable crate should have:

- `license` (or `license-file`)
- `repository`
- `description`
- `edition`
- `rust-version`
- `readme` (path exists relative to crate)

Common failure: `readme = "README.md"` exists only at workspace root.

### docs.rs policy

Pick a policy and encode it:

Facade crates with all features:

```toml
[package.metadata.docs.rs]
all-features = true
```

No-std defaults with std docs:

```toml
[package.metadata.docs.rs]
features = ["std"]
```

### Packaging inclusion/exclusion

Avoid shipping corpora/keys/fixtures accidentally:

```toml
[package]
exclude = ["fuzz/**", "corpus/**", "**/*.der", "**/*.pem"]
```

Verify with `cargo package --list`.

## Preflight: what crates.io will actually see

### The one command that matters

`cargo xtask publish-preflight` should:

- enumerate publishable crates in dependency order
- validate versioned `uselesskey*` dependency snippets in release-facing docs
- run `cargo package` for each
- verify readmes exist and are included
- fail when packaged crates depend on unresolved workspace paths
- optionally verify docs.rs feature policy

If `publish-preflight` does not call `cargo package`, it is not a preflight.

### Extra reality checks

Dry-run leaves first:

```bash
cargo publish -p <leaf-crate> --dry-run
```

### Feature promises

Validate no-default-features claims:

```bash
cargo check -p <crate> --no-default-features
```

## Publish ordering

With microcrates, ordering matters.

Required:

- authoritative publish list or computed topo sort
- include every publishable crate
- order leaves first, then dependents

Recommended implementation:

- `xtask publish-plan` command prints:
  - ordered crate list
  - `publish = false` status
  - versions
  - external dependency blockers
- output plan in CI logs

## CI wiring

### PR workflow

- `cargo xtask fmt`
- `cargo xtask clippy`
- `cargo xtask test`
- `cargo xtask feature-matrix`
- `cargo xtask bdd`
- `cargo xtask publish-preflight`
- `cargo xtask publish-check`
- `cargo fuzz build`

### Main workflow

Same as PR workflow, optionally add:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

### Release workflow

On `vX.Y.Z` tags:

- run full gate set
- publish in dependency order with `CARGO_REGISTRY_TOKEN`

## Release mechanics

Recommended flow:

1. bump versions
2. update changelogs and versioned dependency snippets
3. merge to `main` with green CI
4. tag `vX.Y.Z`
5. publish in dependency order
6. optional release notes

Indexing lag: if dependency publish fails as “not found,” re-run later.

## Troubleshooting

- “Failed to publish dependency not found” → wait/retry after indexing catches up
- missing metadata (`description/license/readme`) → fix manifest
- path dependency rejected → use versions + workspace inheritance
- docs.rs mismatch → set `package.metadata.docs.rs`
- CI hangs/timeouts → add termination guarantees and reduce mutation parallelism

## Next checklist

- [x] CI runs `publish-check` on PRs
- [x] all non-publish crates have `publish = false`
- [x] docs.rs policy is encoded and validated
- [x] feature-matrix covers `--no-default-features` where promised
- [x] publish plan is complete and topo-ordered
- [x] `cargo package --list` is sane
- [x] dry-run publish rehearsal for leaf crates succeeds
