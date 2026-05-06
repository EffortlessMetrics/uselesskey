# Clippy policy

`uselesskey` treats Clippy as a governed engineering surface. The workspace uses
one strict lint baseline for production code, tests, examples, benchmarks, and
`xtask` automation instead of per-crate taste blocks.

## Goals

- Keep fixture code panic-free, including tests.
- Prevent silent failure patterns such as discarded `Result`s, ignored futures,
  and erased error context.
- Make UTF-8, indexing, time, numeric, file/process, concurrency, and memory
  footguns reviewable before they become fixture behavior.
- Require every temporary exception to have a structured receipt.
- Track Rust 1.94 and 1.95 lint flips before the MSRV bump.

## Active baseline

The active lint levels live in the root manifest under `[workspace.lints.rust]`
and `[workspace.lints.clippy]`. Every workspace member inherits that baseline
with:

```toml
[lints]
workspace = true
```

The machine-readable source of truth is `policy/clippy-lints.toml`. The policy
check compares active lint entries in that ledger with the root manifest.

## No test carveouts

The workspace does not use Clippy test carveouts such as:

```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-panic-in-tests = true
allow-indexing-slicing-in-tests = true
allow-dbg-in-tests = true
```

Tests should return `Result` or use helper assertions that preserve context
instead of using `unwrap`, `expect`, or direct panic calls.

## Suppression style

Use narrow `#[expect(..., reason = "...")]` suppressions only when the code is
more correct than the lint's local heuristic. Do not use silent `#[allow]`
suppressions. Broad category suppressions are not allowed.

Temporary lint exceptions belong in `policy/clippy-debt.toml` with `lint`,
`path`, `owner`, `reason`, and `expires` fields. Expired debt fails the policy
check.

## Crypto/security overlay

This repository generates test-only cryptographic fixture shapes. The lint
policy is intentionally strict about numeric casts, unsafe/memory behavior,
randomness-adjacent review surfaces, and suppression governance. Repo-local
Clippy configuration in `clippy.toml` is reserved for disallowed methods, types,
and macros; it is not used to weaken tests.

## Upgrade tracking

`policy/clippy-lints.toml` tracks planned Rust 1.94 and 1.95 flips. Planned
lints must stay out of the active root manifest until the workspace MSRV reaches
the matching version, then they can move into the active baseline deliberately.

## CI gate

Run:

```bash
cargo xtask check-lint-policy
```

The gate verifies MSRV alignment, workspace lint inheritance, active/planned lint
consistency, absence of test carveouts, suppression style, and debt expiry.
