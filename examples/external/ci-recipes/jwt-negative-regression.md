# JWT Negative Test Regression

Use this when a downstream parser or authorization layer needs stable token
negative classes without committing generated token values.

## Rust Test Path

```toml
[dev-dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["token"] }
```

```rust
use uselesskey::{Factory, NegativeToken, TokenFactoryExt, TokenSpec};

let fx = Factory::deterministic_from_str("downstream-jwt-negative");
let token = fx.token("issuer", TokenSpec::oauth_access_token());

let valid_shape = token.value();
let bad_segment_count = token.negative_value(NegativeToken::BadSegmentCount);
let malformed_base64url = token.negative_value(NegativeToken::MalformedBase64Url);
let alg_none = token.negative_value(NegativeToken::AlgNone);
let bad_audience = token.negative_value(NegativeToken::BadAudience);
```

Assert that parser errors, header-policy errors, and claim-policy errors remain
separate downstream regression classes.

## Bundle Receipt Path

JWT/token negatives are exposed through the OIDC contract-pack bundle when a CI
job needs metadata-only bundle evidence:

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

This proves deterministic token-shape regressions for tests. It does not prove
production token security, issuer policy, provider compatibility, or downstream
verifier correctness.
