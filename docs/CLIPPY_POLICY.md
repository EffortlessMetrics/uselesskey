# Clippy Policy

`uselesskey` treats Clippy as a governed engineering surface, not a local preference file. The workspace uses the Effortless Metrics strict Rust baseline: panic-free production and test code, silent-failure prevention, explicit suppression governance, and reviewability lints that keep fixture code readable.

## Active baseline

The active baseline lives in the root `Cargo.toml` under `[workspace.lints.rust]` and `[workspace.lints.clippy]`. Every workspace package must inherit it with:

```toml
[lints]
workspace = true
```

The policy ledger in `policy/clippy-lints.toml` records the MSRV and the planned Rust 1.94 / 1.95 lint flips that should become active when the workspace MSRV advances.

## No test carveouts

The standard is workspace panic-free, not just production panic-free. Do not add Clippy test carveouts such as `allow-unwrap-in-tests`, `allow-expect-in-tests`, `allow-panic-in-tests`, `allow-indexing-slicing-in-tests`, or `allow-dbg-in-tests`.

Tests should prefer `Result`-returning helpers and explicit assertion helpers over `unwrap`, `expect`, or panic-driven setup.

## Suppression style

Local suppressions must use `#[expect(..., reason = "...")]` with a narrow scope and a human-readable reason. Broad `#[allow(...)]` attributes are policy debt and should be replaced by either:

1. a small code change that satisfies the lint;
2. a narrow `#[expect(..., reason = "...")]`; or
3. a temporary entry in `policy/clippy-debt.toml` with owner, reason, path, lint, and expiry.

## Crypto/security overlay

`uselesskey` is a test-fixture crate, but it deliberately emits secret-shaped cryptographic artifacts. The workspace therefore keeps the stricter crypto/security posture from the shared baseline: no unsafe code, no silent result loss, no unchecked panic-family collapse, and staged numeric correctness lints.

## Policy gate

Run the policy gate with:

```bash
cargo xtask check-lint-policy
```

The gate verifies MSRV alignment, workspace lint inheritance, planned lint consistency, lack of test carveouts, and required debt metadata.
