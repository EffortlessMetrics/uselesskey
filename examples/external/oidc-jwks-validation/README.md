# OIDC/JWKS Validation Fixtures

Use this downstream-shaped example when an OIDC or JWT validator test needs
deterministic JWKS shapes plus key-selection negatives.

User job:

```text
I need deterministic OIDC/JWKS valid and invalid shapes in Rust tests.
```

Dependency:

```toml
[dev-dependencies]
uselesskey = { version = "0.10.0", default-features = false, features = ["rsa", "jwk"] }
```

First imports:

```rust
use uselesskey::jwk::{NegativeJwk, NegativeJwks};
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
```

Positive path:

```text
Factory::deterministic_from_str("external-oidc-jwks")
  -> fx.rsa("issuer", RsaSpec::rs256())
  -> public_jwks() accepted by the example validator
```

Negative paths:

```text
NegativeJwks::DuplicateKid  -> duplicate kid rejection
NegativeJwk::WrongKty       -> wrong kty rejection
NegativeJwk::UnsupportedAlg -> unsupported alg rejection
NegativeJwks::MissingKid    -> missing kid rejection
```

```bash
cargo test
```

The example models a small downstream JWKS validator. It accepts a valid RSA
JWKS and rejects taxonomy-backed fixture shapes for:

- duplicate `kid`
- wrong `kty`
- unsupported `alg`
- missing `kid`

Installed CLI bundle audit path:

```bash
uselesskey bundle --profile oidc --out target/uselesskey-oidc
uselesskey audit-bundle --path target/uselesskey-oidc --out target/uselesskey-oidc-audit
```

This proves fixture shape and negative input generation for validator tests, and
shows how a downstream validator can assert specific rejection classes. It does
not prove OpenID discovery behavior, production signing-key custody, issuer
policy, provider compatibility, or production verifier correctness.
