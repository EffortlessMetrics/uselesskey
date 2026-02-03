# uselesskey

Runtime-generated key and certificate fixtures for tests.

This crate exists for one reason: **stop committing secrets-shaped blobs** (PEM, DER, tokens) into your repo just to make tests pass.

- Generates keys **at runtime** (random or deterministic).
- Emits the **shapes** other libraries want (PKCS#8 PEM/DER, SPKI PEM/DER, temp files).
- Includes **negative fixtures** (corrupt PEM, truncated DER, mismatched keypairs) without checking anything into git.

> **Not for production.** Deterministic keys are predictable by design. Even random-mode keys are intended for tests and local dev.

## Quickstart

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};

let fx = Factory::deterministic_from_env("USELESSKEY_SEED")
    .unwrap_or_else(Factory::random);

let rsa = fx.rsa("issuer", RsaSpec::rs256());

let pkcs8_pem = rsa.private_key_pkcs8_pem();
let spki_der  = rsa.public_key_spki_der();
```

### Tempfile outputs

Some libraries insist on `Path`.

```rust
# use uselesskey::{Factory, RsaSpec, RsaFactoryExt};
let fx = Factory::random();
let rsa = fx.rsa("server", RsaSpec::rs256());

let keyfile = rsa.write_private_key_pkcs8_pem().unwrap();
assert!(keyfile.path().exists());
```

### Negative fixtures (no committed blobs)

```rust
# use uselesskey::{Factory, RsaSpec, RsaFactoryExt};
# use uselesskey::negative::CorruptPem;
let fx = Factory::random();
let rsa = fx.rsa("issuer", RsaSpec::rs256());

let bad_pem = rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
let truncated = rsa.private_key_pkcs8_der_truncated(32);
let mismatched_pub = rsa.mismatched_public_key_spki_der();
```

## Determinism model

Deterministic mode is **order-independent**:

- `seed + (domain, label, spec, variant) -> derived seed -> artifact`
- requesting fixtures in a different order does *not* change results

That makes tests stable even as you add more fixtures over time.

## Repo workflow (xtask)

This repo uses the `cargo xtask` pattern.

```bash
cargo xtask ci      # fmt + clippy + tests
cargo xtask nextest # tests via nextest (optional)
cargo xtask deny    # cargo-deny license/advisory checks (optional)
cargo xtask bdd     # cucumber features
cargo xtask mutants # mutation testing (cargo-mutants)
cargo xtask fuzz    # fuzz targets (cargo-fuzz)
```

Tools are not vendored; install as needed:

```bash
cargo install cargo-mutants
cargo install cargo-fuzz
cargo install cargo-nextest
```

## Layout

- `crates/uselesskey-core` – factory, derivation, caching, sinks, generic corruption helpers
- `crates/uselesskey-rsa` – RSA fixtures (PKCS#8/SPKI/PEM/DER) built on the core
- `crates/uselesskey` – public facade crate
- `crates/uselesskey-bdd` – cucumber BDD harness
- `fuzz/` – `cargo fuzz` targets
- `xtask/` – automation commands

## License

Licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
