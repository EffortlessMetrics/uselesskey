# ADR-0002: Seed Boundary Abstraction

## Status

Accepted

## Context

Prior to PR #243, the `rand` crate's types were leaking through the public API of uselesskey. This created several problems:

- **ABI coupling**: Users were exposed to `rand::SeedableRng` and related traits
- **Version lock-in**: Changes to internal RNG implementation required major version bumps
- **Complex ergonomics**: Users needed to understand rand's type system to use the library
- **Testing friction**: Test code had to import and work with rand types directly

The core issue was that the randomness implementation details were part of the public contract, violating encapsulation principles.

## Decision

We established `Seed` as the stable API boundary for deterministic randomness. The key principles are:

1. **Seed as public boundary**: Users interact with `Seed` (a 32-byte wrapper type), not rand types
2. **RNG as implementation detail**: The internal RNG (currently `rand_chacha::ChaCha20Rng`) is hidden behind the seed boundary
3. **Conversion at the boundary**: `Seed` provides internal conversion to RNG, but this is not part of the public API
4. **Stable representation**: `Seed` can be created from `[u8; 32]`, `&[u8]` (with hashing), or hex strings

```rust
// Public API - users see this
let seed = Seed::from_hex("0123...")?;
let factory = Factory::deterministic(seed);

// Internal - hidden from users
impl Seed {
    fn to_rng(&self) -> ChaCha20Rng {
        // Implementation detail
    }
}
```

## Consequences

### Positive

- **API stability**: The rand crate can be upgraded or replaced without breaking changes
- **Ergonomic simplicity**: Users only need to understand `Seed`, not RNG internals
- **Clear contract**: The boundary between "user input" and "internal randomness" is explicit
- **Test isolation**: Tests can create seeds without understanding rand's type system
- **Future flexibility**: Could switch to different RNG algorithms (e.g., for performance)

### Negative

- **Indirection layer**: One additional type between user input and randomness
- **Conversion overhead**: Minor cost in converting seed bytes to RNG state
- **Documentation burden**: Need to clearly explain the seed concept to new users

## Alternatives Considered

### Expose rand types directly

Keep `rand::SeedableRng` and related types in the public API.

**Rejected because**: Creates tight coupling to rand's release cycle; exposes implementation details; harder to use correctly.

### Use generic RNG trait

Accept any `R: rand::RngCore + rand::SeedableRng` as factory input.

**Rejected because**: Complicates the API with generics; still exposes rand traits; doesn't provide a clean "seed" concept for users.

### String-only seeds

Accept only hex strings as seed input, no typed `Seed` struct.

**Rejected because**: Loses type safety; parsing errors become runtime issues; no clear place for seed-related methods.

### Fixed-size array only

Accept only `[u8; 32]` without a wrapper type.

**Rejected because**: Less self-documenting; no natural place for conversion methods; harder to add validation or debugging support.
