# uselesskey

**Test key fixtures generated at runtime.**

Outputs: PKCS#8 PEM/DER, SPKI PEM/DER, tempfiles, JWK/JWKS, and HMAC secrets. Deterministic mode for stable tests; not for production.

---

This crate exists for one reason: **stop committing secrets-shaped blobs** (PEM, DER, tokens) into your repo just to make tests pass.

- Generates keys **at runtime** (random or deterministic).
- Emits the **shapes** other libraries want (PKCS#8 PEM/DER, SPKI PEM/DER, tempfiles).
- Includes **negative fixtures** (corrupt PEM, truncated DER, mismatched keypairs) without checking anything into git.

> **Not for production.** Deterministic keys are predictable by design. Even random-mode keys are intended for tests and local dev.

## Why this crate?

**Secret incidents aren't about the final state of the code — they're about any commit that contained the secret.**

Secret scanning has shifted the ground under "just commit a dummy key":

- [GitGuardian](https://docs.gitguardian.com/) scans **each commit** in a PR, not just the final state. Even "commit then immediately remove" still triggers incidents.
- [GitHub push protection](https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations/about-push-protection) requires removing blocked secrets from **all commits** before the push can proceed.
- Both support path ignores and exclusions, but their guidance is "minimize exclusions; document why; review periodically."

That combination creates a steady incentive to stop committing anything that *looks* like a key, even if it's fake. This crate turns "security team policy + docs + exceptions" into "one dev-dependency."

### What exists today (and why it's not enough)

> Snapshot: last reviewed 2025-02-03. This is context, not a compatibility matrix.

| Crate | What it does | Gap |
|-------|--------------|-----|
| [`jwk_kit`](https://docs.rs/jwk_kit) | Generate RSA/ES256 keypairs, export PKCS#8 PEM or JWK | No deterministic-from-seed, no negative fixtures |
| [`rcgen`](https://docs.rs/rcgen) | Generate self-signed X.509 certs (pure Rust) | [Deterministic mode requested but not first-class](https://github.com/rustls/rcgen/issues/173) |
| [`test-cert-gen`](https://docs.rs/crate/test-cert-gen) | Generate certs for tests | Shells out to OpenSSL CLI |
| [`x509-test-certs`](https://docs.rs/x509-test-certs) | Ships realistic certs/keys as `const` byte arrays | Forces secret-scanner suppression |

The ecosystem has **keygen**, **certgen**, **JWK tooling**, and **fixture blobs** — but not a "fixture factory" optimized around runtime generation + determinism + negative cases + tempfiles + scanner hygiene.

### What makes uselesskey different

1. **Order-independent determinism** — `seed + (domain, label, spec, variant) → derived seed → artifact`. Adding new fixtures doesn't perturb existing ones. Test order doesn't matter.

2. **Cache-by-identity** — RSA keygen cost pushes teams toward committed fixtures. Per-process caching makes runtime generation cheap enough.

3. **Shape-first outputs** — PKCS#8 PEM/DER, SPKI PEM/DER, tempfiles with sane permissions. Users shouldn't need to know crypto crate internals.

4. **Negative fixtures as first-class** — Corrupt PEM (bad base64, wrong headers, truncation), truncated DER, mismatched keypairs. Teams love committed "broken" blobs because producing them is annoying; this crate makes them cheap and ephemeral.

## Quickstart

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};

let fx = Factory::deterministic_from_env("USELESSKEY_SEED")
    .unwrap_or_else(|_| Factory::random());

let rsa = fx.rsa("issuer", RsaSpec::rs256());

let pkcs8_pem = rsa.private_key_pkcs8_pem();
let spki_der  = rsa.public_key_spki_der();
```

### JWK / JWKS

Enable the `jwk` feature for typed JWKs with JSON helpers.

```rust
# #[cfg(feature = "jwk")]
# {
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};

let fx = Factory::random();
let rsa = fx.rsa("issuer", RsaSpec::rs256());

let jwk = rsa.public_jwk();
let jwk_value = jwk.to_value();
assert_eq!(jwk_value["kty"], "RSA");

let jwks = rsa.public_jwks();
let jwks_value = jwks.to_value();
assert!(jwks_value["keys"].is_array());
# }
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

## Examples

Run the examples with the `full` feature (all algorithms + JWK + X.509):

```bash
cargo run -p uselesskey --example jwks --features "full"
cargo run -p uselesskey --example tempfiles --features "full"
```

## Determinism model

Deterministic mode is **order-independent**:

- `seed + (domain, label, spec, variant) -> derived seed -> artifact`
- requesting fixtures in a different order does *not* change results

That makes tests stable even as you add more fixtures over time.

## Repo workflow (xtask)

This repo uses the `cargo xtask` pattern.

```bash
cargo xtask ci      # fmt + clippy + tests + feature-matrix + bdd + no-blob + mutants + fuzz
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
- `crates/uselesskey-jwk` – typed JWK/JWKS helpers
- `crates/uselesskey-rsa` – RSA fixtures (PKCS#8/SPKI/PEM/DER) built on the core
- `crates/uselesskey-ecdsa` – ECDSA fixtures (ES256/ES384)
- `crates/uselesskey-ed25519` – Ed25519 fixtures
- `crates/uselesskey-hmac` – HMAC secret fixtures (HS256/HS384/HS512)
- `crates/uselesskey-x509` – X.509 fixtures
- `crates/uselesskey` – public facade crate
- `crates/uselesskey-bdd` – cucumber BDD harness
- `fuzz/` – `cargo fuzz` targets
- `xtask/` – automation commands

## Requirements

See `docs/requirements-v0.3.md` for the v0.3 acceptance spec.

## License

Licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
