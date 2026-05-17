# Test OIDC JWKS Validation

Use this guide when a downstream OIDC or JWT validator needs a deterministic
JWKS contract pack with both valid and negative key-set shapes.

## Generate the pack

```bash
cargo run -p uselesskey-cli -- bundle \
  --profile oidc \
  --out target/oidc-fixtures

cargo run -p uselesskey-cli -- verify-bundle \
  --path target/oidc-fixtures

cargo run -p uselesskey-cli -- inspect-bundle \
  --path target/oidc-fixtures
```

The profile writes:

- `jwks/valid.json`
- `jwks/negative-duplicate-kid.json`
- `jwks/negative-missing-kid.json`
- `tokens/valid-rs256.json`
- `tokens/negative-alg-none.json`
- `tokens/negative-bad-audience.json`
- `receipts/materialization.json`
- `receipts/audit-surface.json`

## Positive case

Serve or load `target/oidc-fixtures/jwks/valid.json` in the downstream validator
test. The positive case should prove that the validator can load the fixture
pack and select a key from a normal JWKS shape.

## Negative cases

Use `target/oidc-fixtures/jwks/negative-duplicate-kid.json` when the validator
should reject ambiguous key selection. The file contains two distinct key shapes
with the same `kid`.

Use `target/oidc-fixtures/jwks/negative-missing-kid.json` when the validator
should reject or fail key selection for a key without `kid` metadata.

## Rust test lane

For Rust tests that do not need files, use the public fixture surface directly:

```toml
[dev-dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["rsa", "jwk"] }
```

```rust
use uselesskey::jwk::NegativeJwks;
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

let fx = Factory::deterministic_from_str("oidc-negative");
let issuer = fx.rsa("issuer", RsaSpec::rs256());
let jwks = issuer.public_jwks();

let duplicate_kid = jwks.negative_value(NegativeJwks::DuplicateKid);
assert!(validator_rejects(duplicate_kid));
```

Replace `validator_rejects` with the downstream validator assertion. The useful
assertion is the validator's rejection reason, not just that JSON parsing failed.

## Scanner-safety note

The OIDC profile is scanner-safe by default. It is intended for key-set parsing,
token-shape parsing, and validator failure-path tests. Keep generated files
under `target/` and verify them in CI instead of committing generated payloads.

## What this does not prove

- It does not prove OpenID discovery behavior.
- It does not prove production signing-key custody.
- It does not prove cryptographic correctness.
- It does not prove real JWT signature validation unless your downstream test
  adds runtime signing fixtures and adapter-specific assertions.

## Evidence

```bash
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask no-blob
```
