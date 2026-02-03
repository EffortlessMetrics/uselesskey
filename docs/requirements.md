# Requirements

## Problem

Secret scanners (GitGuardian, GitHub secret scanning, etc.) are doing their job: they flag anything that *looks* like a key.

Tests also do their job: they want realistic inputs (PEM/DER, tokens, headers) and they want them *now*.

The failure mode is predictable:

- someone checks in a “sample” private key, token, or API key
- scanners flag it
- you burn time triaging/rotating/revoking something that was never meant to exist
- worse: it ends up in commit history forever

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
- Perfect scanner evasion. (If a scanner flags runtime output, that’s a downstream integration issue.)

## Constraints

- Keep dependencies reasonable.
- Cross-platform support (Linux/macOS/Windows).
- Avoid global mutable state in the library API.
