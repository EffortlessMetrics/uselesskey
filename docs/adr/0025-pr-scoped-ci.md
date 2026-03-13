# ADR-0025: PR-Scoped CI

## Status
Accepted

## Context
Running all tests on every PR is slow and expensive. Many PRs only affect a subset of crates.

## Decision
CI analyzes git diff to determine impacted crates and runs only relevant tests:
- Changed Rust files → run fmt, clippy, tests for impacted crates
- Changed Cargo.toml → run full test suite
- Changed docs only → run minimal checks

Build plan generated in xtask determines test scope.

## Consequences

**Positive:**
- Faster CI for most PRs
- Lower CI costs
- Faster feedback loop

**Negative:**
- Risk of missing cross-crate impacts
- Build plan logic must be maintained
- May need manual full-run for some changes

## Alternatives Considered
- **Always run all tests:** Slow, expensive
- **Manual scoping:** Error-prone, inconsistent
- **Merge-based testing:** Too late to catch issues
