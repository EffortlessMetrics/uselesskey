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
oracles and are NOT panic-family. A future migration may introduce fallible
assertion helpers (`ensure_eq`, `require_some`); that is a separate policy
decision.

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

- **Stage A (current)** — Clippy panic-family at `warn`. `cargo xtask
  check-no-panic-family` runs advisory-only, reporting findings.
- **Stage B** — debt is moved into `policy/no-panic-allowlist.toml` with
  owner/reason/expiry; the checker becomes blocking; new findings outside the
  allowlist fail CI.
- **Stage C** — Clippy panic-family lints flip to `deny`. The allowlist is the
  only legitimate route to a panic-family call site.

## Workflow

```bash
# 1. Find new findings.
cargo xtask check-no-panic-family

# 2. Generate a candidate allowlist file (stays under target/).
cargo xtask no-panic propose

# 3. Review proposed entries; copy reviewed ones into
#    policy/no-panic-allowlist.toml with owner, reason, classification,
#    and expiry. Re-run.

cargo xtask check-no-panic-family
```

## What `check-no-panic-family` enforces

- Detect panic-family calls in workspace Rust sources.
- Match each finding to an allowlist entry by `path + family + selector`.
- In `mode = "blocking"`, fail on unallowlisted findings.
- Fail on **expired** allowlist entries.
- Fail on **stale** entries (entry exists but no matching finding).
- Warn on `last_seen` drift (line/column moved more than the configured
  tolerance).
- Write `target/no-panic.md` and `target/no-panic.json` reports.
