# ADR-0003: Order-Independent Determinism

## Status

Accepted

## Context

Test fixtures need to be deterministic for reproducibility. However, naive approaches to deterministic fixture generation have a critical flaw: test execution order affects the generated values.

Consider a test suite where fixtures are generated sequentially:

```rust
// If tests run in order A, B, C:
test_a() -> fixture_1 = rng.gen()  // uses seed state 0
test_b() -> fixture_2 = rng.gen()  // uses seed state 1
test_c() -> fixture_3 = rng.gen()  // uses seed state 2

// If tests run in order C, B, A:
test_c() -> fixture_1 = rng.gen()  // uses seed state 0 (different fixture!)
test_b() -> fixture_2 = rng.gen()  // uses seed state 1
test_a() -> fixture_3 = rng.gen()  // uses seed state 2
```

This causes several problems:

- **Flaky tests**: Test results depend on execution order
- **Cache invalidation**: Adding a new test perturbs all subsequent fixtures
- **Parallel test issues**: Concurrent tests race for RNG state
- **Debugging difficulty**: Cannot reproduce specific fixture values reliably

## Decision

We implement order-independent determinism using a derivation function that computes each artifact's randomness from its identity, not from RNG state position.

The derivation formula is:

```
seed + artifact_id → derived_seed → artifact
```

Where `artifact_id` is a tuple of:

- **domain**: The key type category (e.g., "rsa", "ecdsa", "ed25519")
- **label**: User-provided identifier (e.g., "issuer", "client-1")
- **spec_fingerprint**: Hash of the specification (e.g., RSA key size, ECDSA curve)
- **variant**: Optional modifier (e.g., "mismatch", "corrupt:header")
- **derivation_version**: Algorithm version for future compatibility

Implementation uses BLAKE3 keyed hashing:

```rust
fn derive_seed(master_seed: &Seed, artifact_id: &ArtifactId) -> Seed {
    let mut hasher = blake3::Hasher::new_keyed(master_seed.as_bytes());
    hasher.update(artifact_id.domain.as_bytes());
    hasher.update(artifact_id.label.as_bytes());
    hasher.update(&artifact_id.spec_fingerprint);
    hasher.update(artifact_id.variant.as_bytes());
    hasher.update(&[artifact_id.derivation_version]);
    Seed::from_bytes(hasher.finalize().as_bytes())
}
```

## Consequences

### Positive

- **Test order independence**: Tests can run in any order without affecting fixture values
- **Stable additions**: Adding new fixtures doesn't change existing ones
- **Parallel safety**: Each fixture derivation is independent; no shared mutable state
- **Cache-by-identity**: Natural cache key `(domain, label, spec, variant)` works correctly
- **Reproducibility**: Same seed + artifact_id always produces the same artifact
- **Debuggability**: Can regenerate any specific fixture from its identity

### Negative

- **Computational cost**: Each derivation requires hashing (mitigated by caching)
- **Artifact identity complexity**: Must track all components of artifact_id
- **No sequential ergonomics**: Cannot just "get next key" without specifying identity
- **Version management**: Algorithm changes require derivation_version bumps

## Alternatives Considered

### Sequential RNG with fixed order

Use a single RNG with deterministic test ordering.

**Rejected because**: Test frameworks don't guarantee order; parallel tests break this; adding tests perturbs existing ones.

### Per-test RNG instances

Each test gets its own RNG seeded from test name.

**Rejected because**: Test names can change; doesn't work well with parameterized tests; harder to share fixtures between tests.

### Global registry with explicit registration

Tests register fixtures in a known order before use.

**Rejected because**: Requires initialization order; complex lifecycle management; doesn't work with lazy test generation.

### Counter-based RNG (CBRNG)

Use a parallel-safe RNG like `rand_xoshiro` with jump-ahead.

**Rejected because**: Still requires coordinating which counter positions each fixture uses; doesn't solve the identity problem; less flexible than hash-based derivation.
