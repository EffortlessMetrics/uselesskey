# Requirements

## Problem

Secret scanners (GitGuardian, GitHub secret scanning, etc.) are doing their job: they flag anything that *looks* like a key.

Tests also do their job: they want realistic inputs (PEM/DER, tokens, headers) and they want them *now*.

The failure mode is predictable:

- someone checks in a "sample" private key, token, or API key
- scanners flag it
- you burn time triaging/rotating/revoking something that was never meant to exist
- worse: it ends up in commit history forever

### Why this keeps happening

- Some scanners evaluate **each commit** in a PR, not just the final state. "Commit then immediately remove" still triggers incidents. ([GitGuardian docs](https://docs.gitguardian.com/internal-monitoring/prevent/detect-secrets-in-real-time-in-github))
- Both GitHub and GitGuardian support path ignores/workspace exclusions, but their guidance is "minimize exclusions; document why; review periodically." ([GitHub docs](https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/excluding-folders-and-files-from-secret-scanning))

This creates a steady incentive to stop committing anything that *looks* like a key, even if it's fake.

## Landscape

Existing solutions each have gaps:

| Crate | What it does | Gap |
|-------|--------------|-----|
| [`jwk_kit`](https://docs.rs/jwk_kit) | Generate RSA/ES256 keypairs, export PKCS#8 PEM or JWK | No deterministic-from-seed, no negative fixtures |
| [`rcgen`](https://docs.rs/rcgen) | Generate self-signed X.509 certs (pure Rust) | [Deterministic mode requested but not first-class](https://github.com/rustls/rcgen/issues/173) |
| [`test-cert-gen`](https://docs.rs/crate/test-cert-gen) | Generate certs for tests | Shells out to OpenSSL CLI |
| [`x509-test-certs`](https://docs.rs/x509-test-certs) | Ships realistic certs/keys as `const` byte arrays | Forces secret-scanner suppression |

The ecosystem has **keygen**, **certgen**, **JWK tooling**, and **fixture blobs** — but not a "fixture factory" optimized around runtime generation + determinism + negative cases + tempfiles + scanner hygiene.

## Goals

### 1) No committed secret-shaped blobs

- Fixtures are generated at runtime.
- Deterministic mode is supported so outputs are stable without committing artifacts.

### 2) Stable, order-independent determinism

- The *same* `(domain, label, spec, variant)` must produce the same artifact,
  regardless of when/where it’s requested.
- Adding new fixtures must not perturb existing ones.

### 3) Ergonomics over ceremony

- One-liner creation (`fx.rsa("issuer", RsaSpec::rs256())`).
- Output in the forms libraries want (PKCS#8 PEM/DER, SPKI PEM/DER, tempfiles).

### 4) Negative fixtures are first-class

- Corrupt-but-shaped PEM.
- Truncated DER.
- Mismatched public keys.

### 5) Safe-by-default *for tests*

- Debug output must not dump key material.
- Tempfiles default to restrictive permissions on Unix (`0600`).

## Non-goals

- Production key management.
- Hardware-backed keys.
- Enforcing cryptographic best practices beyond what tests need.
- Perfect scanner evasion. (If a scanner flags runtime output, that's a downstream integration issue.)

## Target adopters

This is a **dev-dependency niche** with a useful shape:

- **High frequency**: lots of repos need JWT/TLS tests
- **Recurring pain**: scanner noise, fixture sprawl, OpenSSL in CI
- **Low switching cost**: drop in a dev-dep, delete committed fixtures
- **High trust requirement**: naming, docs, and guardrails matter

### When uselesskey makes sense

- Teams that want to remove committed test keys/certs
- Projects with strict secret scanning policies
- CI environments where OpenSSL installation is friction
- Codebases with many JWT or TLS-related tests

### When uselesskey doesn't make sense

- Teams already comfortable with "commit fixtures and ignore that directory"
- Projects with existing internal fixture generators
- Environments where shelling out to OpenSSL is fine
- One-off scripts that don't need determinism or negative fixtures

## Constraints

- Keep dependencies reasonable.
- Cross-platform support (Linux/macOS/Windows).
- Avoid global mutable state in the library API.
