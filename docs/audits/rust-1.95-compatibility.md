# Rust 1.95 Compatibility Audit

**Date:** 2026-05-08  
**Auditor:** Claude (automated)  
**Branch:** `probe/rust-1.95-compat`  
**Toolchain:** `rustc 1.95.0 (59807616e 2026-04-14)`  
**Current MSRV:** 1.92  
**Target MSRV:** 1.95 (proposed in `chore/msrv-rust-1.95`)

---

## Summary

The workspace is **compatible** with Rust 1.95. No compilation errors were found.
Eight Clippy lints newly enforced under `-D warnings` in 1.95 required concrete code fixes,
all in `xtask` and one test file. No public API changes were needed.

---

## Commands run

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --exclude uselesskey-bdd --locked --no-run
cargo xtask gate --check
```

---

## Results

### `cargo fmt --all -- --check`

**Status:** PASS — no formatting differences.

### `cargo check --workspace --all-targets --all-features --locked`

**Status:** PASS — zero errors across all 48 crates.

### `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`

**Status:** PASS after 8 targeted fixes (see below). No remaining errors.

**Failures before fixes:**

| File | Line | Lint | Fix applied |
|------|------|------|-------------|
| `xtask/src/policy.rs` | 438 | `clippy::collapsible_match` | Collapsed `if` into match guard on `"blocking"` arm |
| `xtask/src/policy.rs` | 448 | `clippy::collapsible_match` | Collapsed `if` into match guard on `"no-new-debt"` arm |
| `xtask/src/pr_bundles.rs` | 565 | `clippy::useless_conversion` | Removed redundant `.into_iter()` in `.zip()` argument |
| `xtask/src/pr_bundles.rs` | 1272 | `clippy::while_let_loop` | Converted `loop { let Some(...) = ... else { break }; ... }` to `while let` |
| `xtask/src/receipt.rs` | 67 | `clippy::unnecessary_sort_by` | `sort_by(\|a, b\| b.1.cmp(&a.1))` → `sort_by_key(\|b\| Reverse(b.1))` |
| `crates/uselesskey-rustcrypto/tests/snapshots_rustcrypto.rs` | 42 | `clippy::unnecessary_cast` | `modulus_bits as u32` → `modulus_bits` (already `u32`) |
| `crates/uselesskey-rustcrypto/tests/snapshots_rustcrypto.rs` | 68 | `clippy::unnecessary_cast` | `.bits() as u32` → `.bits()` (already `u32`) |
| `crates/uselesskey-rustcrypto/tests/snapshots_rustcrypto.rs` | 93 | `clippy::unnecessary_cast` | `modulus_bits as u32` → `modulus_bits` (already `u32`) |

All 8 fixes are behaviour-preserving. The `collapsible_match` fixes use match guards
for clearer intent. The cast removals reflect that `BigUint::bits()` returns `u32`
in the version of the `rsa` crate used here.

### `cargo test --workspace --all-features --exclude uselesskey-bdd --locked --no-run`

**Status:** PASS — all test binaries compiled successfully.

### `cargo xtask gate --check`

**Status:** PASS — fmt check, cargo check, clippy, and test compile all passed.

---

## New 1.95 lints affecting this repo

The following Clippy lints newly triggered under 1.95 `-D warnings`:

| Lint | Category | Disposition |
|------|----------|-------------|
| `clippy::collapsible_match` | style | Fixed in xtask/policy.rs |
| `clippy::useless_conversion` | complexity | Fixed in xtask/pr_bundles.rs |
| `clippy::while_let_loop` | style | Fixed in xtask/pr_bundles.rs |
| `clippy::unnecessary_sort_by` | perf | Fixed in xtask/receipt.rs |
| `clippy::unnecessary_cast` | complexity | Fixed in uselesskey-rustcrypto test |

Lints from `policy/clippy-lints.toml` **staged** for 1.94/1.95 activation
(not yet active, measured in PR 4):

- `same_length_and_capacity`
- `manual_ilog2`
- `decimal_bitwise_operands`
- `needless_type_cast`
- `disallowed_fields` (hold — needs field policy)
- `manual_checked_ops`
- `manual_take`
- `manual_pop_if`
- `duration_suboptimal_units`
- `unnecessary_trailing_comma`

---

## New 1.95 compiler lints

The following `rustc` lints are available and clean under 1.95
(verified by `cargo check` with no new errors):

| Lint | Status |
|------|--------|
| `const_item_interior_mutations` | Clean — no occurrences found |
| `function_casts_as_integer` | Clean — no occurrences found |
| `unused_visibilities` | Clean — no occurrences found |

These are ready for activation in `PR 3 — policy/rust-1.95-lints`.

---

## No-panic status

- Mode: `no-new-debt`
- Baseline total: 4,224 existing findings
- No new debt introduced by the 8 compatibility fixes.

---

## Staged API features (not used in this PR)

These Rust 1.95 features are candidates for use in `PR 6 — refactor/rust-1.95-builder-cleanups`:

| Feature | Candidate use |
|---------|---------------|
| `Vec::push_mut` | JWK/JWKS builder, manifest construction, receipt generation |
| `if let` guards in match | no-panic scanner, file/lint policy matchers |
| `cfg_select!` | rustls/aws-lc/ring backend routing |
| Atomic `update`/`try_update` | Only if existing CAS loops found (none confirmed yet) |

---

## Conclusion

- No compilation breakage.
- 8 Clippy issues fixed, all in `xtask` (internal tooling) and one test file.
- No public API changes required.
- Workspace is ready for MSRV bump to 1.95 (`PR 2`).
- rustc lint floor additions (`PR 3`) are confirmed clean.
- Staged Clippy ratchets (`PR 4`) need measurement run before activation.
