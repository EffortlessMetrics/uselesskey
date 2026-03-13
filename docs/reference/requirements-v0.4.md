# Requirements: v0.4.0

> RNG boundary cleanup and API hardening

## North star

Public API does not leak rand crate types; `Seed` is the stable boundary between user code and RNG implementation.

## Product requirements

### PR-1: Seed as API boundary

The `Seed` type is the only RNG-related type users interact with directly.

- Users never see `rand::SeedableRng` or related traits in public API
- Users never see `rand::RngCore` or `rand::CryptoRng` in signatures
- Internal RNG implementation is an encapsulated detail

### PR-2: Stable ABI contract

The seed-to-artifact derivation path has a stable fingerprint.

- Same seed + artifact_id always produces same artifact
- Internal RNG algorithm changes require derivation version bump
- No breaking changes to derivation without version increment

### PR-3: No rand types in public signatures

All public functions use `Seed` or derived types, never rand primitives.

- Factory methods accept `Seed` or `&Seed`
- Extension trait signatures use `Seed` references
- rand types only appear in internal modules

## System requirements

### SR-1: Encapsulated RNG

The RNG implementation is hidden behind the Seed abstraction.

- rand crate is an internal implementation detail
- Users cannot depend on specific RNG algorithms
- Future RNG changes do not affect public API

### SR-2: Backward compatibility

Existing code using `Seed` continues to work without changes.

- `Seed::new(bytes)` behavior unchanged
- `Seed::from_text(text)` behavior unchanged
- Determinism guarantees preserved

## Release/ops requirements

### RR-1: Version bump on derivation changes

If RNG algorithm changes, derivation version must increment.

- Documented in CHANGELOG.md
- Breaking change requires major or minor version bump per semver

### RR-2: Migration guide

If any user-visible changes occur, provide migration documentation.

- docs/how-to/migration.md updated if needed
- README examples remain accurate

## Acceptance gates

### Gate 1: API cleanliness

```bash
# No rand types in public API
cargo doc -p uselesskey --no-deps 2>&1 | grep -i "rand::" || echo "PASS"
```

### Gate 2: Determinism preserved

```bash
# Existing determinism tests pass
cargo test -p uselesskey-core determinism
```

### Gate 3: Core tests pass

```bash
cargo test -p uselesskey-core-seed -p uselesskey-core-factory -p uselesskey-core
```

### Gate 4: Full test suite

```bash
cargo xtask gate
```

## PR Reference

- [#243](https://github.com/EffortlessMetrics/uselesskey/pull/243) - refactor(rng): hide rand ABI behind seed boundaries

## Related ADRs

- [ADR-0002: Seed Boundary Abstraction](../adr/0002-seed-boundary-abstraction.md)
