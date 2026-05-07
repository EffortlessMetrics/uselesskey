# Clippy / Rust lint policy

> Authoritative file: `policy/clippy-lints.toml`. Lints are configured in
> `[workspace.lints]` in the root `Cargo.toml`. Crate `Cargo.toml` files opt
> in via `[lints]\nworkspace = true`. The xtask `check-lint-policy` enforces
> consistency.

## Why

`uselesskey` is a crypto/security workspace whose users embed our fixtures in
their tests. Surprising panics, silent result loss, byte-boundary indexing
mistakes, or `dbg!()` left in adapters are all unacceptable. Clippy catches
these *shapes* close to the code; the [no-panic policy](NO_PANIC_POLICY.md)
owns the *exception ledger*.

## The dual-rail design

```
Clippy lints           ← fast, IDE-visible, catches local bad shapes
no-panic checker       ← owns the exception ledger (path + family + selector)
file-policy checker    ← owns non-Rust surface allowlist
lint-policy checker    ← verifies every crate inherits the shared rules
```

Clippy is the immediate detector. The no-panic checker (`cargo xtask
check-no-panic-family`) is the *authoritative* exception mechanism: it carries
owner, classification, reason, expiry, and selector identity — none of which
fit in `#[expect(...)]` attributes alone.

## Stage A (current)

- Panic-family Clippy lints are at **`warn`** while debt is being mapped.
- `cargo xtask check-no-panic-family` runs in **advisory** mode (reports but
  does not block CI).
- `cargo xtask no-panic propose` writes a candidate baseline allowlist.
- The strict baseline (Stage C) flips panic-family lints to `deny` once the
  allowlist is the authoritative ledger.

## Suppression style

- **No bare `#[allow(...)]`.** Use `#[expect(..., reason = "...")]` only.
- **No `clippy.toml` test carveouts** (`allow-unwrap-in-tests` etc.).
- Receipted panic-family exceptions live in
  `policy/no-panic-allowlist.toml` (see [NO_PANIC_POLICY.md](NO_PANIC_POLICY.md)).
- Clippy-debt entries live in `policy/clippy-debt.toml` with owner, reason,
  and expiry.

## Planned MSRV-staged flips

`policy/clippy-lints.toml` lists lints planned to flip on at MSRV 1.94 and
1.95. `cargo xtask check-lint-policy` verifies they are NOT activated before
their target MSRV.

## What `check-lint-policy` enforces

- Workspace MSRV matches `policy/clippy-lints.toml`.
- Every member crate has `[lints]\nworkspace = true`.
- No `clippy.toml` test carveouts.
- **No bare `#[allow(...)]`** in crate sources — every suppression must carry a
  `reason = "..."` clause (or use `#[expect(..., reason = ...)]`).
- All `clippy-debt.toml` entries have owner, reason, and a non-expired date.
- Planned MSRV-staged lints are not activated too early.
