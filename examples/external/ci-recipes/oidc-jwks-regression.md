# OIDC/JWKS Verifier Regression

Use this when a downstream verifier needs stable JWKS positives and negative
key-selection classes.

## Rust Test Path

```toml
[dev-dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["rsa", "jwk"] }
```

```rust
use uselesskey::jwk::{NegativeJwk, NegativeJwks};
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

let fx = Factory::deterministic_from_str("downstream-oidc-jwks");
let issuer = fx.rsa("issuer", RsaSpec::rs256());

let valid = issuer.public_jwks().to_value();
let missing_kid = issuer.public_jwks().negative_value(NegativeJwks::MissingKid);
let duplicate_kid = issuer.public_jwks().negative_value(NegativeJwks::DuplicateKid);
let wrong_kty = issuer.public_jwk().negative_value(NegativeJwk::WrongKty);
```

Assert that the downstream verifier accepts `valid` and maps each negative
fixture to its own rejection class.

## Installed Bundle Path

```bash
uselesskey bundle --profile oidc --out target/uselesskey-oidc
uselesskey verify-bundle target/uselesskey-oidc
uselesskey inspect-bundle target/uselesskey-oidc
uselesskey audit-bundle \
  target/uselesskey-oidc \
  --ci \
  --expect-profile oidc \
  --policy strict \
  --out target/uselesskey-oidc-audit
```

## Boundary

This proves local OIDC/JWKS fixture shape and bundle consistency. It does not
prove OpenID discovery, provider compatibility, production signing-key custody,
or downstream verifier correctness.
