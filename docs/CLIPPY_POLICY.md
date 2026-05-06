# Clippy policy

`uselesskey` treats Clippy as a governed engineering surface. The workspace policy is shared with the broader Effortless Metrics Rust platform: strict defaults, explicit suppressions, and expiring debt rather than silent carveouts.

## Baseline

The root `Cargo.toml` owns the active lint baseline in `[workspace.lints.rust]` and `[workspace.lints.clippy]`. Every workspace member inherits it with:

```toml
[lints]
workspace = true
```

The active baseline covers:

- panic-free production and test code (`unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`);
- silent-failure prevention (`let _` on important results, ignored `Result::ok`, ignored `map_err`);
- AST, UTF-8, string, slice, file, path, async, unsafe, memory, numeric, and trait-correctness footguns;
- good-taste reviewability lints that reduce allocation noise and make public contracts easier to audit;
- suppression governance.

## No test carveouts

Tests follow the same panic-free posture as production code. Do not add these `clippy.toml` carveouts:

```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-panic-in-tests = true
allow-indexing-slicing-in-tests = true
allow-dbg-in-tests = true
```

Prefer fallible tests that return `Result` and propagate fixture setup errors with `?`.

## Suppression style

Use narrow `#[expect(..., reason = "...")]` suppressions when a lint exception is intentional and local. Do not use broad `#[allow(...)]` suppression unless a policy check has a dedicated exception for generated code or a similarly reviewed surface.

Example:

```rust
#[expect(
    clippy::arithmetic_side_effects,
    reason = "test vector arithmetic intentionally exercises wrapping behavior"
)]
fn wrapping_vector_case() {
    // ...
}
```

## Policy ledgers

- `policy/clippy-lints.toml` records the active platform posture and planned Rust 1.94/1.95 lint flips.
- `policy/clippy-debt.toml` records temporary repo-local debt with lint, path, owner, reason, and expiry.
- `policy/no-panic-allowlist.toml` is reserved for semantic panic-family exceptions using path + family + selector identity.
- `policy/non-rust-allowlist.toml` records reviewed non-Rust surfaces with owner, reason, classification, and CI coverage.

Run `cargo xtask check-lint-policy` before review to verify the policy files and workspace inheritance stay coherent.
