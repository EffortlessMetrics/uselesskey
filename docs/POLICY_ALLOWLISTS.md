# Policy allowlists overview

This document describes the shared structure of every policy allowlist used
in `uselesskey`. The principle is constant:

> **Deny by default. Allow by receipt. Expire exceptions. Measure drift.**

## Files

| File                                  | Purpose                                            | Checker                                |
|---------------------------------------|----------------------------------------------------|----------------------------------------|
| `policy/clippy-lints.toml`            | Lint posture, MSRV, planned 1.94/1.95 flips        | `cargo xtask check-lint-policy`        |
| `policy/clippy-debt.toml`             | Receipted Clippy warn-stage debt with expiry       | `cargo xtask check-lint-policy`        |
| `policy/no-panic-allowlist.toml`      | Receipted panic-family call sites                  | `cargo xtask check-no-panic-family`    |
| `policy/non-rust-allowlist.toml`      | Receipted non-Rust tracked files                   | `cargo xtask check-file-policy`        |

## Common rules

- **Identity, not coordinates.** Allowlist entries match by *what* (path +
  family + selector, or path-glob + kind), never by line/column.
- **Owner + reason + classification are required.** Every entry has a human
  owner and a written justification.
- **Expiry.** `expires` is an ISO-8601 date. Past entries are rejected.
- **Drift.** `last_seen` (no-panic) and unmatched-entry detection
  (file-policy) surface drift.
- **`covered_by`.** Every non-Rust file class with `production`, `test`, or
  `tooling` classification must point to a CI/xtask command that exercises it.

## Reports

Each checker writes both human-readable and machine-readable artifacts:

```
target/no-panic.md       target/no-panic.json
target/file-policy.md    target/file-policy.json
target/lint-policy.md    target/lint-policy.json
target/policy-report.md  target/policy-report.json
```

`cargo xtask policy-report` aggregates all four into a single review surface.

## Process

```
1. Run `cargo xtask check-no-panic-family` and `check-file-policy`.
2. If new findings exist:
   a. Run `cargo xtask no-panic propose` to write a candidate allowlist
      under target/policy-proposed/.
   b. Review proposed entries; add owner, reason, classification, and
      expiry; copy into policy/.
3. Re-run the checkers.
4. Commit policy changes alongside the code changes that triggered them.
```

The checkers never mutate `policy/`. Proposals are emitted under `target/` so
that human review is required.
