# No-panic policy

> Authoritative file: `policy/no-panic-allowlist.toml`. Enforced by `cargo
> xtask check-no-panic-family`. See also [CLIPPY_POLICY.md](CLIPPY_POLICY.md).

## Definition

> *Panic-free* in `uselesskey` means **no unreceipted panic-family behavior in
> production or tests**.

The panic family includes:

- `unwrap`
- `expect`
- `panic!`
- `todo!`
- `unimplemented!`
- `unreachable!`
- unchecked indexing/slicing (`a[i]`, `&s[i..]`)
- `get(...).unwrap()`
- unchecked time subtraction (`Instant::duration_since`, etc. that can panic)
- `Result`-returning bodies that `unwrap()` internally

Test assertion macros (`assert!`, `assert_eq!`, `assert_ne!`) are still test
oracles and are NOT panic-family. The `uselesskey-test-support` crate
provides fallible alternatives (`ensure!`, `ensure_eq!`, `require_some`,
`require_ok`) that compose with `Result<()>`-returning tests for migrations
that want to remove `unwrap`/`expect` from setup code while keeping
panicking assertion macros for the actual oracle.

```rust
use uselesskey_test_support::{ensure_eq, require_ok, TestResult};

#[test]
fn parses_round_trip() -> TestResult<()> {
    let parsed = require_ok("42".parse::<i32>(), "parse 42")?;
    ensure_eq!(parsed, 42);
    Ok(())
}
```

## Identity

The no-panic checker matches by **`path + family + selector`** — never by
line/column. `last_seen.line` and `last_seen.column` are advisory hints used
to surface drift.

```toml
[[allow]]
id = "panic-0001"
path = "crates/uselesskey-core/src/sink/mod.rs"
family = "expect"
classification = "test_helper"
owner = "core"
explanation = "Sink test helper; will move to fallible assertion helper."
expires = "2026-09-01"

[allow.selector]
kind = "method_call"
container = "tempfile_text_roundtrip"
callee = "expect"
receiver_fingerprint = "TempArtifact::new(...)"

[allow.last_seen]
line = 50
column = 14
```

### Classifications

| Classification           | Meaning                                                |
|--------------------------|--------------------------------------------------------|
| `production`             | Live runtime path; should be near-zero, hard to renew. |
| `test_helper`            | Pure test scaffolding; migrate to fallible API.        |
| `fixture`                | Fixture builder where panic equals "test bug".         |
| `infallible_invariant`   | Compiler/data-driven invariants; document the proof.   |
| `build_script`           | `build.rs` setup.                                      |

## Stages

- **Stage A** — Clippy panic-family at `warn`. The checker runs advisory.
- **Stage A.5 (current)** — `mode = "no-new-debt"`: the checker now blocks
  any panic-family finding *not* in either `policy/no-panic-allowlist.toml`
  or `policy/no-panic-baseline.toml`. Existing baselined debt does not need
  manual classification; new debt fails CI.
- **Stage B** — debt is moved out of the baseline and into the allowlist
  with owner/reason/expiry; the baseline shrinks toward empty; the checker
  flips to `mode = "blocking"`.
- **Stage C** — Clippy panic-family lints flip to `deny`. The allowlist is
  the only legitimate route to a panic-family call site.

## Workflow

```bash
# 1. Run the checker.
cargo xtask check-no-panic-family

# 2a. Refresh the existing baseline after a deliberate burndown PR. This drops
#     entries/counts that disappeared and refuses to add new debt.
cargo xtask no-panic baseline

# 2b. Reset the baseline only for the initial snapshot or an explicit
#     repo-policy reset PR.
cargo xtask no-panic baseline --reset

# 2c. Generate a candidate allowlist file (stays under target/) for entries
#     ready to graduate from the baseline into the receipted allowlist.
cargo xtask no-panic propose
```

## Modes

| Mode           | When the checker fails                                                              |
|----------------|--------------------------------------------------------------------------------------|
| `advisory`     | Never. Only writes the report.                                                       |
| `no-new-debt`  | Findings outside both `no-panic-allowlist.toml` and `no-panic-baseline.toml`.        |
| `blocking`     | Any finding outside `no-panic-allowlist.toml` (the baseline is ignored).             |

The `expired` and `stale` allowlist signals fail in both `no-new-debt` and
`blocking`.

## What `check-no-panic-family` enforces

- Detect panic-family calls in workspace Rust sources.
- Match each finding against `policy/no-panic-allowlist.toml`
  (`path + family + selector`) and `policy/no-panic-baseline.toml`
  (`path + family + selector + snippet`, with occurrence counts).
- In `mode = "no-new-debt"`, fail on findings not in either set.
- In `mode = "blocking"`, fail on unallowlisted findings (baseline ignored).
- Fail on **expired** allowlist entries.
- Fail on **stale** allowlist entries (entry exists but no matching finding).
- Surface **stale baseline** entries (candidate for removal on next regenerate).
- Write `target/no-panic.md` and `target/no-panic.json` reports.
