# Clippy Policy

`uselesskey` treats Clippy as a governed engineering surface, not as a local taste file. The workspace policy is designed to converge on the Effortless Metrics platform baseline: panic-free production and test code, silent-failure prevention, suppression governance, and reviewability lints that make security-sensitive fixture code easier to audit.

## Current rollout phase

This repository is in the staged policy phase:

1. The root manifest declares the shared strict workspace lint block.
2. `policy/clippy-lints.toml` records the machine-readable policy and Rust 1.93/1.94/1.95 ratchet plan.
3. `policy/clippy-debt.toml` is the only place for temporary lint debt.
4. Member-level `[lints] workspace = true` inheritance is intentionally a follow-up PR after debt triage, because the existing workspace still contains panic-driven tests and other known violations.

## Suppression style

Use narrow `#[expect(..., reason = "...")]` suppressions when a lint exception is truly intentional. Do not use silent `#[allow(...)]` attributes for new exceptions.

Good:

```rust,ignore
#[expect(clippy::indexing_slicing, reason = "generated lookup table has fixed bounds")]
let value = TABLE[index];
```

Bad:

```rust,ignore
#[allow(clippy::indexing_slicing)]
let value = TABLE[index];
```

## No test carveouts

Do not add Clippy test carveouts to `clippy.toml`, including:

- `allow-unwrap-in-tests = true`
- `allow-expect-in-tests = true`
- `allow-panic-in-tests = true`
- `allow-indexing-slicing-in-tests = true`
- `allow-dbg-in-tests = true`

The target state is workspace panic-free, not production-only panic-free.

## Policy checks

Run:

```bash
cargo xtask check-lint-policy
```

The check verifies that the manifest, `clippy.toml`, and policy ledgers remain coherent. It also validates required debt fields and fails expired debt.

## Planned ratchets

- Rust 1.93: align workspace MSRV with the platform baseline and enable member lint inheritance.
- Rust 1.94: track `same_length_and_capacity`, `manual_ilog2`, `decimal_bitwise_operands`, and `needless_type_cast`.
- Rust 1.95: track `disallowed_fields`, `manual_checked_ops`, `manual_take`, `manual_pop_if`, `duration_suboptimal_units`, and `unnecessary_trailing_comma`.
