# Architecture

## Workspace layout

- `crates/uselesskey-core`
  - derivation (BLAKE3 keyed hash)
  - cache (DashMap keyed by ArtifactId)
  - sinks (tempfile outputs)
  - generic negative-fixture helpers (PEM/DER mangling)

- `crates/uselesskey-rsa`
  - RSA keypair generator (RustCrypto `rsa`)
  - encodings: PKCS#8 private, SPKI public
  - mismatch fixtures (variant-derived keypairs)
  - optional `jwk` feature

- `crates/uselesskey`
  - facade re-exporting the stable public API

- `crates/uselesskey-bdd`
  - cucumber feature tests; kept out of the main crate’s dependency graph

- `fuzz/`
  - cargo-fuzz targets (negative fixture functions + parser stress)

- `xtask/`
  - fmt/clippy/test/bdd/mutants/fuzz runners

## Deterministic derivation

In deterministic mode:

```
master_seed + artifact_id -> derived_seed -> RNG -> artifact
```

`artifact_id` is:

- domain (string, stable)
- label (string)
- spec_fingerprint (BLAKE3 hash of stable spec bytes)
- variant (string)
- derivation version (u16)

The derived seed uses a **keyed BLAKE3 hasher** with length-prefixing for strings.
This gives stable results and avoids order coupling.

## Cache behavior

A `Factory` caches artifacts per `ArtifactId`.

- deterministic mode: cache is an optimization; derivation is stable regardless
- random mode: cache makes repeated calls consistent within a process

Artifacts are stored as `Arc<dyn Any + Send + Sync>` and downcast on retrieval.

## Why “variant”

Variant strings solve a bunch of test cases cleanly:

- `"good"`: normal fixture
- `"mismatch"`: same label/spec, different keypair, used for mismatch negative tests
- `"corrupt:*"`: future: derive deterministic corruption patterns without randomness

The variant is part of the artifact id, so it does not collide with the “good” fixture.
